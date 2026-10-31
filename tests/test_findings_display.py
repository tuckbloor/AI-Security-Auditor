"""Regression coverage for empty findings, filters and source highlights."""
from pathlib import Path
import runpy
import sys

from auditor import Finding
from findings_view import (ALL_SEVERITIES, build_findings_rows,
                           filter_findings_rows, render_highlighted_excerpt)
from tests.test_app_smoke import FakeStreamlit, ROOT


def fake_finding() -> Finding:
    return Finding('app/Http/Controllers/Demo.php', 7, 'HIGH',
                   'Unsafe dynamic evaluation', '[withheld]', 'Avoid eval',
                   'Code injection', 'abcdef1234')


def test_rule_findings_display_without_any_ai_reviews():
    rows = build_findings_rows([fake_finding()], {}, [])
    assert len(rows) == 1
    assert rows[0]['File'] == 'app/Http/Controllers/Demo.php'
    assert rows[0]['Status'] == 'Not AI-reviewed'
    assert filter_findings_rows(rows, ALL_SEVERITIES, '') == rows


def test_filters_are_explicit_and_clearable():
    rows = build_findings_rows([fake_finding()], {}, [])
    assert filter_findings_rows(rows, 'LOW', '') == []
    assert filter_findings_rows(rows, ALL_SEVERITIES, 'nothing-matches') == []
    assert filter_findings_rows(rows, ALL_SEVERITIES, 'demo.php') == rows
    assert filter_findings_rows(rows, 'HIGH', 'CODE INJECTION') == rows
    assert filter_findings_rows(rows, ALL_SEVERITIES, 'Not AI-reviewed') == rows


def test_combined_results_include_unverified_ai_discovery():
    discovery = [{'severity': 'MEDIUM', 'category': 'XSS', 'path': 'resources/views/home.blade.php',
                  'line': 12, 'id': 'disc1'}]
    rows = build_findings_rows([fake_finding()], {}, discovery)
    assert len(rows) == 2
    assert rows[1]['Origin'] == 'AI discovered (unverified)'
    assert rows[1]['Status'] == 'Requires human verification'


def test_exact_source_line_is_highlighted_and_html_escaped():
    raw = '    6: $safe = "<img src=x onerror=alert(1)>";\n    7: eval($payload);\n    8: return true;'
    html = render_highlighted_excerpt(raw, 7)
    assert html.count('source-target') == 1
    assert '⚠ REPORTED LINE' in html
    assert 'eval($payload)' in html
    assert '&lt;img' in html
    assert '<img' not in html
    assert html.index('source-target') < html.index('eval($payload)')
    assert 'source-number">7</span>' in html


def test_escapes_scripts_even_on_flagged_line():
    html = render_highlighted_excerpt('   24: <script>evil()</script>', 24)
    assert '<script>' not in html
    assert '&lt;script&gt;' in html
    assert 'source-target' in html


class FindingsUI(FakeStreamlit):
    def __init__(self, selected_project):
        super().__init__(selected_project)
        self.tables = []
        self.markdowns = []
        self.selects = []

    def dataframe(self, rows, **kwargs):
        self.tables.append(rows)

    def markdown(self, text, **kwargs):
        self.markdowns.append(text)

    def selectbox(self, label, options, **kwargs):
        self.selects.append((label, list(options)))
        return next(iter(options), None)


def test_actual_app_renders_findings_and_highlight(monkeypatch, tmp_path):
    project = tmp_path / 'test-project'
    project.mkdir()
    (project / 'artisan').write_text('', encoding='utf-8')
    (project / 'Demo.php').write_text('<?php\nfunction unsafe($payload) {\n    eval($payload);\n}\n', encoding='utf-8')
    ui = FindingsUI(project)
    monkeypatch.setitem(sys.modules, 'streamlit', ui)
    monkeypatch.syspath_prepend(str(ROOT))
    import ollama_client
    monkeypatch.setattr(ollama_client, 'installed_models', lambda: [])
    runpy.run_path(str(ROOT / 'app.py'), run_name='__main__')
    # Final findings table must not be empty, even with zero AI reviews.
    assert any(table and isinstance(table, list) and table[0].get('File') == 'Demo.php'
               for table in ui.tables)
    assert any('Showing 1 of 1 findings' in text for text in ui.markdowns)
    assert any('Select a finding to inspect' in label for label, _ in ui.selects)
    assert any('source-target' in text and 'eval($payload)' in text for text in ui.markdowns)
