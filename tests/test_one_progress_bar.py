"""Guard against accidental creation of 2–3 progress bars again."""
import runpy
import sys
from types import SimpleNamespace
from tests.test_two_stage_flow import StageTrackingUI, ROOT

class ProgressUI(StageTrackingUI):
    def __init__(self, project, ai):
        super().__init__(project, ai=ai)
        self.progress_calls = []
        self.progress_updates = []

    def progress(self, value, **kwargs):
        self.progress_calls.append((value, self.column_depth))
        parent = self
        class Bar:
            def progress(self, value, **details):
                parent.progress_updates.append((value, details.get('text', '')))
        return Bar()


def test_one_single_full_width_progress_bar(monkeypatch, tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'artisan').write_bytes(b'')
    (project / 'demo.php').write_bytes(b'<?php\neval($input);\n')
    ui = ProgressUI(project, ai=False)
    monkeypatch.setitem(sys.modules, 'streamlit', ui)
    monkeypatch.syspath_prepend(str(ROOT))
    import ollama_client
    monkeypatch.setattr(ollama_client, 'installed_models', lambda: [])
    runpy.run_path(str(ROOT / 'app.py'), run_name='__main__')
    assert ui.progress_calls == [(0.0, 0)]
    assert ui.progress_updates
    assert ui.progress_updates[-1][0] == 1.0
    assert all(0 <= value <= 1 for value, _ in ui.progress_updates)
    assert ui.session_state.scan_result['result'].findings


def test_app_only_creates_one_progress_widget():
    text = (ROOT / 'app.py').read_text(encoding='utf-8')
    assert text.count('st.progress(') == 1
    assert 'python_bar = st.progress(' not in text
    assert 'ai_progress = st.progress(' not in text


def test_ai_stage_uses_same_bar_and_does_not_finish_early(monkeypatch, tmp_path):
    import json
    project = tmp_path / 'laravel-project'
    project.mkdir()
    (project / 'artisan').write_bytes(b'')
    (project / 'Demo.php').write_bytes(b'<?php\neval($input);\n')
    ui = ProgressUI(project, ai=True)
    monkeypatch.setitem(sys.modules, 'streamlit', ui)
    monkeypatch.syspath_prepend(str(ROOT))
    import ollama_client
    import ai_engine
    monkeypatch.setattr(ollama_client, 'installed_models', lambda: [SimpleNamespace(name='test:latest')])
    model_call_count = []

    def model_stub(model, prompt, *, system, **kwargs):
        # The bar must not be 100% before the Ollama model has finished.
        assert ui.progress_updates[-1][0] < 1.0
        model_call_count.append(system)
        if system == ai_engine.REVIEW_SYSTEM:
            yield json.dumps({'assessment':'Potential issue', 'verdict':'needs_review',
                              'confidence':'low', 'rationale':'Review input boundary',
                              'suggested_new_line':''})
        else:
            yield '{"issues": []}'

    def response_stream(parts, **kwargs):
        from ai_engine import AIEvent
        for part in parts:
            yield AIEvent(kind='token', value=part, elapsed_seconds=0.1)

    monkeypatch.setattr(ai_engine, 'stream_ollama_json', model_stub)
    monkeypatch.setattr(ai_engine, 'stream_with_heartbeat', response_stream)
    runpy.run_path(str(ROOT / 'app.py'), run_name='__main__')
    assert model_call_count
    assert ui.progress_calls == [(0.0, 0)], 'Never create another bar for stage 2'
    assert ui.progress_updates[-1][0] == 1.0
    assert all(x <= y for (x,_), (y,_) in zip(ui.progress_updates, ui.progress_updates[1:]))
    assert any('Stage 1' in text for _, text in ui.progress_updates)
    assert any('Stage 2' in text for _, text in ui.progress_updates)
    assert len(ui.session_state.scan_result['reviews']) == 1
