"""Read-only heuristic scanner for local application source code.

These findings are leads, not validated vulnerabilities. Never execute scanned code.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import hashlib
import json
import os
import re

IGNORE_DIRS = {
    '.git', '.venv', 'venv', 'node_modules', 'vendor', 'dist', 'build',
    '__pycache__', 'storage', '.idea', '.next', 'coverage', '.pytest_cache',
    '.mypy_cache', '.nuxt', '.output', 'public/build', 'target', '.gradle',
}
TEST_DIRS = {'tests', 'test', '__tests__', '__fixtures__', 'fixtures',
             'sample-project', 'sample-data', 'examples'}
EXTENSIONS = {'.py', '.php', '.js', '.jsx', '.ts', '.tsx', '.vue', '.yaml', '.yml'}
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 4000
MAX_FINDINGS = 2000
SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')

@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    severity: str
    rule: str
    evidence: str  # Never store original potentially sensitive source here.
    advice: str
    category: str
    id: str

@dataclass(frozen=True)
class ScanResult:
    findings: list[Finding]
    scanned_files: int
    frameworks: list[str]
    truncated: bool
    unreadable_files: int

@dataclass(frozen=True)
class Rule:
    severity: str
    name: str
    pattern: re.Pattern
    advice: str
    category: str
    extensions: frozenset[str] | None = None


def rule(severity: str, name: str, expression: str, advice: str, category: str,
         extensions: set[str] | None = None) -> Rule:
    return Rule(severity, name, re.compile(expression, re.I), advice, category,
                frozenset(extensions) if extensions else None)

# Lightweight patterns, not full taint-analysis. Avoid claiming a confirmed exploit.
RULES = [
    rule('HIGH', 'TLS verification disabled', r'\bverify\s*=\s*False\b|CURLOPT_SSL_VERIFYPEER\s*,\s*false|rejectUnauthorized\s*:\s*false',
         'Enable certificate verification and use a trusted CA.', 'Transport security'),
    rule('HIGH', 'Shell command execution', r'\bshell\s*=\s*True\b|\bos\.system\s*\(|\bshell_exec\s*\(|\bpassthru\s*\(|\bchild_process\.exec\s*\(',
         'Avoid executing input as shell commands. Use fixed argument lists and validate inputs.', 'Command injection'),
    rule('HIGH', 'Dynamic code evaluation', r'\b(?<![\w.])eval\s*\(|\bexec\s*\(|\bassert\s*\(\s*\$',
         'Avoid interpreting untrusted strings as executable code.', 'Code injection'),
    rule('HIGH', 'Laravel raw SQL interpolation', r'\b(?:DB::(?:select|statement|unprepared|raw)|(?:whereRaw|havingRaw|orderByRaw))\s*\([^\n]*(?:\$\w+|\{\$\w+\})',
         'Use parameter binding, query builder expressions, and validate variable inputs.', 'SQL injection', {'.php'}),
    rule('HIGH', 'Python SQL string interpolation', r'\bexecute(?:many)?\s*\(\s*(?:f[\'\"]|[^\n]*(?:%\s*\(|\.format\s*\())',
         'Pass user-supplied values using DB-API query parameters.', 'SQL injection', {'.py'}),
    rule('MEDIUM', 'Unescaped HTML sink', r'\.innerHTML\s*=|\bdangerouslySetInnerHTML\b|\{!!\s*\$',
         'Verify whether untrusted data is escaped or correctly sanitised before rendering.', 'Cross-site scripting'),
    rule('HIGH', 'Hardcoded credential candidate', r'\b(?:api[_-]?key|secret[_-]?key|password|access[_-]?token)\s*[:=]\s*[\'\"][^\'\"]{8,}[\'\"]',
         'Move credentials to secure configuration and rotate any exposed secrets.', 'Secret exposure'),
    rule('MEDIUM', 'Unsafe PHP deserialization', r'\bunserialize\s*\(',
         'Avoid unserializing untrusted input; use JSON and validate schemas.', 'Deserialization', {'.php'}),
    rule('MEDIUM', 'Unsafe Python deserialization', r'\bpickle\.(?:loads?|Unpickler)\s*\(',
         'Do not load pickle data from untrusted sources.', 'Deserialization', {'.py'}),
    rule('LOW', 'PHP debug enabled in code', r'\b(?:ini_set\s*\(\s*[\'\"]display_errors|APP_DEBUG\s*=\s*true)\b',
         'Ensure detailed errors and debug output are disabled in production.', 'Information disclosure', {'.php'}),
    rule('MEDIUM', 'Potential path traversal', r'\b(?:send_file|open|file_get_contents|readfile)\s*\(\s*(?:request\.|\$request\s*->)',
         'Constrain requested paths to an approved directory; validate resolved paths.', 'Path traversal'),
]


def allowed_file(path: Path) -> bool:
    if path.name.lower().startswith('.env') or path.name in {'.npmrc', '.pypirc'}:
        return False
    return path.suffix.lower() in EXTENSIONS or path.name.endswith('.blade.php')


def detect_frameworks(root: str | Path) -> list[str]:
    """Only inspect known project indicator files; no code execution."""
    root = Path(root)
    result: list[str] = []
    if (root / 'artisan').is_file():
        result.append('Laravel')
    composer = _read_json(root / 'composer.json')
    require = {**composer.get('require', {}), **composer.get('require-dev', {})} if isinstance(composer, dict) else {}
    if 'laravel/framework' in require and 'Laravel' not in result:
        result.append('Laravel')
    if composer or (root / 'composer.json').is_file():
        result.append('PHP / Composer')
    package = _read_json(root / 'package.json')
    deps = {**package.get('dependencies', {}), **package.get('devDependencies', {})} if isinstance(package, dict) else {}
    if 'vue' in deps:
        result.append('Vue')
    if 'react' in deps:
        result.append('React')
    if 'next' in deps:
        result.append('Next.js')
    if 'django' in (root / 'requirements.txt').read_text(encoding='utf-8', errors='replace').lower() if (root / 'requirements.txt').is_file() else False:
        result.append('Django')
    if (root / 'manage.py').is_file() and 'Django' not in result:
        result.append('Django (possible)')
    if (root / 'pyproject.toml').is_file() or (root / 'requirements.txt').is_file():
        result.append('Python')
    if package or (root / 'package.json').is_file():
        result.append('JavaScript / Node')
    return result or ['Unknown / general source']


def _read_json(path: Path) -> dict:
    try:
        if path.is_file() and path.stat().st_size <= 128_000:
            value = json.loads(path.read_text(encoding='utf-8'))
            return value if isinstance(value, dict) else {}
    except (OSError, ValueError, UnicodeError):
        pass
    return {}


def _is_comment(line: str, ext: str) -> bool:
    line = line.lstrip()
    return line.startswith(('#', '//', '*', '/*', '<!--')) if ext != '.py' else line.startswith('#')


@dataclass(frozen=True)
class ScanEvent:
    kind: str  # progress / complete
    scanned_files: int
    file: str
    result: ScanResult | None = None


def iter_candidate_sources(root: str | Path, *, include_test_files: bool = False):
    """Lazily walk allowed source files; never load an entire project's filenames."""
    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f'Project folder does not exist: {root}')
    ignored = IGNORE_DIRS if include_test_files else IGNORE_DIRS | TEST_DIRS
    for parent, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories[:] = sorted(d for d in directories if d.lower() not in ignored
                                and not (Path(parent) / d).is_symlink())
        for name in sorted(files):
            path = Path(parent) / name
            try:
                if not path.is_symlink() and allowed_file(path) and path.stat().st_size <= MAX_FILE_BYTES:
                    yield path
            except OSError:
                continue


def scan_project_stream(root: str | Path, max_files: int = MAX_FILES, *,
                        include_test_files: bool = False, max_findings: int = MAX_FINDINGS):
    """Generator returning incremental progress and a final result.

    Reads source one line at a time; retains only capped finding metadata.
    """
    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f'Project folder does not exist: {root}')
    findings: list[Finding] = []
    scanned = errors = 0
    truncated = False
    for path in iter_candidate_sources(root, include_test_files=include_test_files):
        if scanned >= max_files:
            truncated = True
            break
        scanned += 1
        relative = path.relative_to(root).as_posix()
        try:
            with path.open('r', encoding='utf-8', errors='replace') as source:
                for number, line in enumerate(source, 1):
                    if _is_comment(line, path.suffix.lower()):
                        continue
                    for candidate in RULES:
                        if candidate.extensions and path.suffix.lower() not in candidate.extensions:
                            continue
                        if candidate.pattern.search(line[:10_000]):
                            key = f'{relative}:{number}:{candidate.name}'
                            findings.append(Finding(relative, number, candidate.severity,
                                                    candidate.name, '[source withheld until review]',
                                                    candidate.advice, candidate.category,
                                                    hashlib.sha256(key.encode()).hexdigest()[:14]))
                            if len(findings) >= max_findings:
                                truncated = True
                                break
                    if truncated:
                        break
        except (OSError, UnicodeError):
            errors += 1
        yield ScanEvent('progress', scanned, relative)
        if truncated:
            break
    result = ScanResult(findings, scanned, detect_frameworks(root), truncated, errors)
    yield ScanEvent('complete', scanned, '', result)


def scan_project(root: str | Path, max_files: int = MAX_FILES, *, include_test_files: bool = False,
                 max_findings: int = MAX_FINDINGS) -> ScanResult:
    """Backwards compatible synchronous wrapper for the generator."""
    for event in scan_project_stream(root, max_files, include_test_files=include_test_files,
                                     max_findings=max_findings):
        if event.kind == 'complete':
            return event.result
    raise RuntimeError('Source scanning did not return a final result')


def findings_as_dicts(findings: list[Finding]) -> list[dict]:
    return [asdict(f) for f in findings]
