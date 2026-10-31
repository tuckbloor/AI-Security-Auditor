"""Guarded one-line fix proposals. Existing source must be inspected and user-approved."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from difflib import unified_diff
from pathlib import Path
import hashlib
import os
import tempfile
from datetime import datetime, timezone

MAX_EDITABLE = 1_000_000
SOURCE_SUFFIXES = {'.php', '.py', '.js', '.jsx', '.ts', '.tsx', '.vue'}
BLOCKED_FILES = {'.env', '.env.local', '.env.production', 'composer.lock', 'package-lock.json'}


@dataclass(frozen=True)
class ProposedChange:
    path: str
    line: int
    expected_hash: str
    new_line: str
    diff: str


def locate_source(root: str | Path, relative_path: str) -> Path:
    base = Path(root).resolve(strict=True)
    rel = Path(relative_path)
    if rel.is_absolute() or any(p in ('.', '..') for p in rel.parts) or not relative_path:
        raise ValueError('Unsafe file path: absolute or parent-relative paths are forbidden.')
    path = base / rel
    if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != base.parent):
        # Do not edit a linked file or traverse linked directories.
        raise ValueError('Cannot edit through symbolic links.')
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(base) or not resolved.is_file():
        raise ValueError('Target must be an existing source file inside the selected project.')
    if resolved.name.lower() in BLOCKED_FILES or resolved.name.lower().startswith('.env') or resolved.suffix.lower() not in SOURCE_SUFFIXES:
        raise ValueError('Editing this file type is not supported.')
    if resolved.stat().st_size > MAX_EDITABLE:
        raise ValueError('File is too large for an automatic edit.')
    return resolved


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _decode(raw: bytes) -> str:
    if b'\x00' in raw:
        raise ValueError('Cannot edit binary files.')
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ValueError('Only UTF-8 source files support reviewed edits.') from exc


def make_proposal(root: str | Path, relative_path: str, line_number: int,
                  new_line: str) -> ProposedChange:
    path = locate_source(root, relative_path)
    if not isinstance(new_line, str) or not new_line.strip() or '\n' in new_line or '\r' in new_line:
        raise ValueError('Fix must contain exactly one nonempty source line.')
    raw = path.read_bytes()
    old = _decode(raw)
    lines = old.splitlines(keepends=True)
    if line_number < 1 or line_number > len(lines):
        raise ValueError('The flagged line does not exist in this file.')
    current = lines[line_number - 1]
    ending = '\r\n' if current.endswith('\r\n') else '\n' if current.endswith('\n') else ''
    old_line = current.rstrip('\r\n')
    if old_line.strip() == new_line.strip():
        raise ValueError('The suggested fix does not change the original source line.')
    lines[line_number - 1] = new_line + ending
    replacement = ''.join(lines)
    if path.suffix.lower() == '.py':
        try:
            ast.parse(replacement, filename=relative_path)
        except SyntaxError as exc:
            raise ValueError(f'Suggested change does not parse as Python: {exc}') from exc
    diff = ''.join(unified_diff(old.splitlines(keepends=True), replacement.splitlines(keepends=True),
                                fromfile=f'a/{relative_path}', tofile=f'b/{relative_path}'))
    return ProposedChange(relative_path, line_number, _hash(raw), new_line, diff)


def apply_proposal(root: str | Path, change: ProposedChange, backup_directory: str | Path) -> Path:
    """Apply approved line edit only if file matches snapshot. Backup stored outside project."""
    path = locate_source(root, change.path)
    current = path.read_bytes()
    if _hash(current) != change.expected_hash:
        raise ValueError('Source changed since review; rescan before editing.')
    # Re-validate requested change; do not trust stale proposal data.
    regenerated = make_proposal(root, change.path, change.line, change.new_line)
    if regenerated.expected_hash != change.expected_hash:
        raise ValueError('File changed during review; no edit applied.')
    text = _decode(current)
    lines = text.splitlines(keepends=True)
    old_line = lines[change.line - 1]
    ending = '\r\n' if old_line.endswith('\r\n') else '\n' if old_line.endswith('\n') else ''
    lines[change.line - 1] = change.new_line + ending
    updated = ''.join(lines).encode('utf-8')
    backups = Path(backup_directory).expanduser().resolve()
    # Backup must not be inside a project: prevents accidental leakage and scanning backups.
    project = Path(root).resolve()
    if backups == project or backups.is_relative_to(project):
        raise ValueError('Backups must be stored outside the selected project.')
    backups.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup = backups / f'{stamp}-{path.name}-{_hash(current)[:12]}.bak'
    with backup.open('xb') as handle:
        handle.write(current)
    # Preserve permission bits; use temp file + atomic replace (Windows file must be closed).
    fd, temp_name = tempfile.mkstemp(prefix='.auditor-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, path.stat().st_mode)
        # Final best-effort recheck to narrow concurrent-change race.
        if _hash(path.read_bytes()) != change.expected_hash:
            raise ValueError('Source changed during save; backup created but source not overwritten.')
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    if path.read_bytes() != updated:
        raise OSError('File verification after save failed.')
    return backup


def source_excerpt(root: str | Path, relative: str, line: int, radius: int = 5) -> tuple[str, str]:
    path = locate_source(root, relative)
    raw = path.read_bytes()
    lines = _decode(raw).splitlines()
    if not (1 <= line <= len(lines)):
        raise ValueError('Flagged line no longer exists. Rescan.')
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    snippet = '\n'.join(f'{i:>5}: {lines[i-1][:300]}' for i in range(start, end + 1))
    return snippet, _hash(raw)
