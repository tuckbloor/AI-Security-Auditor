"""Launch the actual app entrypoint with a lightweight Streamlit test double.

This catches errors in the on-load and rule-scan paths without needing to open a GUI.
It is not a substitute for testing the real Streamlit interface on Windows.
"""
from pathlib import Path
import runpy
import sys
import types

ROOT = Path(__file__).resolve().parents[1]


class Session(dict):
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError as exc:
            raise AttributeError(key) from exc

    def __setattr__(self, key, value):
        self[key] = value


class Placeholder:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def container(self):
        return self

    def __getattr__(self, key):
        return lambda *args, **kwargs: None


class TrackedColumn(Placeholder):
    def __init__(self, streamlit):
        self.streamlit = streamlit

    def __enter__(self):
        self.streamlit.column_depth += 1
        return self

    def __exit__(self, *args):
        self.streamlit.column_depth -= 1


class FakeStreamlit(types.ModuleType):
    def __init__(self, selected_project):
        super().__init__('streamlit')
        self.sidebar = Placeholder()
        self.session_state = Session(selected_project=str(selected_project))
        self.scan_clicked = False
        self.column_depth = 0
        self.buttons_shown = []
        self.status_depths = []

    def columns(self, sizes, **kwargs):
        return [TrackedColumn(self) for _ in range(len(sizes) if isinstance(sizes, list) else sizes)]

    def button(self, label, **kwargs):
        self.buttons_shown.append(label)
        if 'Python scan only' in label and not self.scan_clicked:
            self.scan_clicked = True
            return True
        return False

    def number_input(self, label, *args, **kwargs):
        return kwargs.get('value', args[2] if len(args) > 2 else 30)

    def checkbox(self, label, **kwargs):
        return kwargs.get('value', False)

    def multiselect(self, label, options, **kwargs):
        return kwargs.get('default', options)

    def selectbox(self, label, options, **kwargs):
        return next(iter(options), None)

    def text_input(self, label, **kwargs):
        return ''

    def status(self, *args, **kwargs):
        self.status_depths.append(self.column_depth)
        return Placeholder()

    def expander(self, *args, **kwargs):
        return Placeholder()

    def progress(self, *args, **kwargs):
        return Placeholder()

    def empty(self, *args, **kwargs):
        return Placeholder()

    def __getattr__(self, key):
        return lambda *args, **kwargs: None


def test_app_entrypoint_loads_and_runs_a_real_rule_scan(monkeypatch, tmp_path):
    project = tmp_path / 'example-project'
    (project / 'routes').mkdir(parents=True)
    (project / 'routes' / 'web.php').write_text('<?php\n// Test project\n', encoding='utf-8')
    (project / 'app' / 'Http' / 'Controllers').mkdir(parents=True)
    (project / 'app' / 'Http' / 'Controllers' / 'Foo.php').write_text(
        '<?php\nclass Foo {}\n', encoding='utf-8')
    streamlit = FakeStreamlit(project)
    monkeypatch.setitem(sys.modules, 'streamlit', streamlit)
    monkeypatch.syspath_prepend(str(ROOT))
    import ollama_client
    monkeypatch.setattr(ollama_client, 'installed_models', lambda: [])
    runpy.run_path(str(ROOT / 'app.py'), run_name='__main__')
    assert streamlit.scan_clicked
    record = streamlit.session_state.get('scan_result')
    assert record is not None
    assert record['root'] == str(project.resolve())
    assert record['result'].scanned_files >= 1
    assert record['finished'] is True
    # Regression: Audit started from a button must not render inside a column.
    assert streamlit.status_depths == [0]  # Python scan is full-width
    assert streamlit.session_state.audit_started is True
    audit_log = runpy.run_path(str(ROOT / 'app.py'), run_name='__main__')['render_audit_log']
    assert '&lt;script&gt;' in audit_log(['path: <script>'])
    assert '<script>' not in audit_log(['path: <script>'])
    # Once the audit runs, neither scan button is displayed again until a new project.
    streamlit.buttons_shown.clear()
    runpy.run_path(str(ROOT / 'app.py'), run_name='__main__')
    assert not any('Start Python + Ollama audit' in label or 'Python scan only' in label
                   for label in streamlit.buttons_shown)
