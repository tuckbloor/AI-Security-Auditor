"""Bounded, read-only repository tools for the Ollama security investigation agent.

Source content is never executed. Tool outputs are untrusted evidence, not commands.
"""
from __future__ import annotations

import hashlib
from time import monotonic
from pathlib import Path

from auditor import (IGNORE_DIRS, TEST_DIRS, MAX_FILE_BYTES, allowed_file,
                     iter_candidate_sources)
from ollama_client import redact_secrets

MAX_TOOL_OUTPUT = 6500
MAX_FILES_TO_SEARCH = 1500
MAX_TOOL_SECONDS = 6


class AgentToolError(ValueError):
    pass


class ProjectTools:
    def __init__(self, root: str | Path, *, include_tests: bool = False):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise AgentToolError('Selected project folder is not a directory')
        self.include_tests = include_tests
        self.read_lines: dict[str, set[int]] = {}
        self.issues: list[dict] = []
        self.tools_used: list[str] = []

    def _source(self, relative: str) -> tuple[Path, str]:
        if not isinstance(relative, str) or not relative or len(relative) > 500:
            raise AgentToolError('Invalid relative filename')
        rel = Path(relative.replace('\\', '/'))
        if rel.is_absolute() or '..' in rel.parts or ':' in relative or rel == Path('.'):
            raise AgentToolError('Only relative paths inside the project are allowed')
        excluded = IGNORE_DIRS if self.include_tests else IGNORE_DIRS | TEST_DIRS
        if any(part.lower() in excluded for part in rel.parts[:-1]):
            raise AgentToolError('Protected or excluded directory')
        path = self.root / rel
        if any(part.is_symlink() for part in [path, *path.parents] if part != self.root):
            raise AgentToolError('Symlink paths are not available')
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(self.root)
        except (OSError, ValueError) as exc:
            raise AgentToolError('Requested source file does not exist inside the project') from exc
        if not resolved.is_file() or not allowed_file(resolved):
            raise AgentToolError('This is not an allowed source file')
        if resolved.stat().st_size > MAX_FILE_BYTES:
            raise AgentToolError('File exceeds source reading limit')
        return resolved, resolved.relative_to(self.root).as_posix()

    def list_files(self, prefix: str = '', limit: int = 30) -> dict:
        limit = max(1, min(50, int(limit)))
        prefix = str(prefix or '').replace('\\', '/').lstrip('/')
        if '..' in Path(prefix).parts:
            raise AgentToolError('Invalid path prefix')
        matches = []
        deadline = monotonic() + MAX_TOOL_SECONDS
        for count, path in enumerate(iter_candidate_sources(self.root, include_test_files=self.include_tests), 1):
            if count > MAX_FILES_TO_SEARCH or monotonic() > deadline:
                break
            relative = path.relative_to(self.root).as_posix()
            if relative.lower().startswith(prefix.lower()):
                matches.append(relative)
                if len(matches) >= limit:
                    break
        return {'files': matches, 'limit': limit}

    def search_code(self, term: str, limit: int = 12) -> dict:
        term = str(term or '').strip()
        if len(term) < 2 or len(term) > 100 or '\n' in term:
            raise AgentToolError('Search phrase must contain 2–100 characters')
        limit = max(1, min(20, int(limit)))
        findings = []
        deadline = monotonic() + MAX_TOOL_SECONDS
        for count, path in enumerate(iter_candidate_sources(self.root, include_test_files=self.include_tests), 1):
            if count > MAX_FILES_TO_SEARCH or monotonic() > deadline:
                break
            rel = path.relative_to(self.root).as_posix()
            try:
                with path.open(encoding='utf-8', errors='replace') as handle:
                    for line, text in enumerate(handle, 1):
                        if term.casefold() in text.casefold():
                            findings.append({'path': rel, 'line': line,
                                             'snippet': redact_secrets(text.strip()[:220])})
                            if len(findings) >= limit:
                                return {'matches': findings, 'limit': limit}
            except (OSError, UnicodeError):
                continue
        return {'matches': findings, 'limit': limit}

    def read_file(self, path: str, start_line: int = 1, end_line: int = 50) -> dict:
        file, relative = self._source(path)
        start = int(start_line)
        end = int(end_line)
        if start < 1 or end < start or end - start > 59:
            raise AgentToolError('Read 1–60 lines per request')
        lines = []
        with file.open(encoding='utf-8', errors='replace') as handle:
            for number, text in enumerate(handle, 1):
                if number > end:
                    break
                if number >= start:
                    lines.append(f'{number}: {redact_secrets(text.rstrip()[:400])}')
                    self.read_lines.setdefault(relative, set()).add(number)
        return {'path': relative, 'start': start, 'end': end, 'lines': lines}

    def report_finding(self, path: str, line: int, severity: str,
                       category: str, explanation: str) -> dict:
        _, rel = self._source(path)
        number = int(line)
        if number not in self.read_lines.get(rel, set()):
            raise AgentToolError('Read the reported source line before reporting a finding')
        level = str(severity).upper()
        if level not in {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}:
            raise AgentToolError('Invalid severity')
        category = str(category).strip()[:100]
        explanation = redact_secrets(str(explanation).strip()[:1500])
        if not category or len(explanation) < 12:
            raise AgentToolError('Finding needs a category and meaningful explanation')
        issue_id = 'ai-' + hashlib.sha256(f'{rel}:{number}:{category}'.encode()).hexdigest()[:14]
        if not any(x['id'] == issue_id for x in self.issues):
            self.issues.append({'id': issue_id, 'path': rel, 'line': number,
                                'severity': level, 'category': category,
                                'assessment': explanation,
                                'source': 'AI-suspected / requires human verification'})
        return {'accepted': True, 'id': issue_id, 'path': rel, 'line': number}

    def execute(self, name: str, arguments: dict) -> dict:
        if not isinstance(arguments, dict):
            raise AgentToolError('Tool arguments must be an object')
        mapping = {'list_files': self.list_files, 'search_code': self.search_code,
                   'read_file': self.read_file, 'report_finding': self.report_finding}
        if name not in mapping:
            raise AgentToolError(f'Tool is not available: {name}')
        self.tools_used.append(name)
        try:
            response = mapping[name](**arguments)
        except TypeError as exc:
            raise AgentToolError('Tool arguments do not match its signature') from exc
        return response


TOOL_SPECS = [
    {'type': 'function', 'function': {
        'name': 'list_files', 'description': 'List real source filenames in the selected project',
        'parameters': {'type': 'object', 'properties': {
            'prefix': {'type': 'string'}, 'limit': {'type': 'integer'}}}}},
    {'type': 'function', 'function': {
        'name': 'search_code', 'description': 'Search actual source files for a literal phrase',
        'parameters': {'type': 'object', 'properties': {
            'term': {'type': 'string'}, 'limit': {'type': 'integer'}}, 'required': ['term']}}},
    {'type': 'function', 'function': {
        'name': 'read_file', 'description': 'Read 1–60 real source lines for security evidence',
        'parameters': {'type': 'object', 'properties': {
            'path': {'type': 'string'}, 'start_line': {'type': 'integer'},
            'end_line': {'type': 'integer'}}, 'required': ['path']}}},
    {'type': 'function', 'function': {
        'name': 'report_finding',
        'description': 'Report a suspected issue on a source line already inspected via read_file',
        'parameters': {'type': 'object', 'properties': {
            'path': {'type': 'string'}, 'line': {'type': 'integer'},
            'severity': {'type': 'string'}, 'category': {'type': 'string'},
            'explanation': {'type': 'string'}},
            'required': ['path', 'line', 'severity', 'category', 'explanation']}}},
]
