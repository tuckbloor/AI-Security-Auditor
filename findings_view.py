"""Presentation helpers for security leads. All displayed code remains escaped."""
from __future__ import annotations

from html import escape
import re
from typing import Iterable

from ollama_client import redact_secrets

ALL_SEVERITIES = 'All severities'
_COLUMNS = ('Origin', 'Severity', 'Category', 'File', 'Line', 'Status', 'Key')
_SOURCE_PATTERN = re.compile(r'^\s*(\d+): (.*)$')


def build_findings_rows(findings: Iterable, reviews: dict, discovery: Iterable[dict]) -> list[dict]:
    """Never omit rule findings simply because Ollama has not reviewed them."""
    rows: list[dict] = []
    for finding in findings:
        entry = reviews.get(finding.id)
        review = entry.get('review', {}) if isinstance(entry, dict) else {}
        rows.append({'Origin': 'Python lead', 'Severity': finding.severity,
                     'Category': finding.category, 'File': finding.path, 'Line': finding.line,
                     'Status': review.get('verdict', 'Not AI-reviewed'), 'Key': finding.id})
    for issue in discovery:
        rows.append({'Origin': 'AI discovered (unverified)', 'Severity': issue['severity'],
                     'Category': issue['category'], 'File': issue['path'], 'Line': issue['line'],
                     'Status': 'Requires human verification', 'Key': issue['id']})
    return rows


def filter_findings_rows(rows: list[dict], severity: str = ALL_SEVERITIES, search: str = '') -> list[dict]:
    needle = search.strip().casefold()
    return [row for row in rows
            if (severity == ALL_SEVERITIES or row['Severity'] == severity)
            and (not needle or needle in ' '.join(str(row.get(k, '')) for k in
                                           ('File', 'Category', 'Origin', 'Status')).casefold())]


def render_highlighted_excerpt(excerpt: str, flagged_line: int) -> str:
    """Render numbered source excerpt with an obvious highlighted target line.

    The original source is never interpreted as HTML. Sensitive values are
    redacted before escaping. No project text can inject markup or scripts.
    """
    output = ['<div class="source-lines" role="region" aria-label="Source code excerpt">']
    for source_line in redact_secrets(excerpt).splitlines():
        match = _SOURCE_PATTERN.match(source_line)
        if not match:
            output.append(f'<div class="source-line">{escape(source_line)}</div>')
            continue
        number = int(match.group(1))
        body = escape(match.group(2))
        is_target = number == flagged_line
        css = 'source-line source-target' if is_target else 'source-line'
        badge = '<span class="target-flag">⚠ REPORTED LINE</span>' if is_target else ''
        output.append(f'<div class="{css}"><span class="source-number">{number}</span>'
                      f'<span class="source-text">{body}</span>{badge}</div>')
    output.append('</div>')
    return '\n'.join(output)
