"""Regression tests that actually exercise Python-then-AI audit ordering."""
import json
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace

from tests.test_app_smoke import FakeStreamlit, Placeholder, ROOT


class StageTrackingUI(FakeStreamlit):
    def __init__(self, project, *, ai):
        super().__init__(project)
        self.ai = ai
        self.events = []

    def button(self, label, **kwargs):
        self.buttons_shown.append(label)
        if not self.scan_clicked and (('Start Python + Ollama audit' in label) if self.ai
                                      else ('Python scan only' in label)):
            self.scan_clicked = True
            return True
        return False

    def status(self, label, **kwargs):
        self.status_depths.append(self.column_depth)
        self.events.append(('status', label))
        return Placeholder()

    def dataframe(self, rows, **kwargs):
        self.events.append(('table', rows))
        return None

    def success(self, message, **kwargs):
        self.events.append(('python-summary', message))


def run_two_stage(monkeypatch, tmp_path, *, ai):
    project = tmp_path / 'laravel-sample'
    (project / 'app' / 'Http' / 'Controllers').mkdir(parents=True)
    (project / 'artisan').write_text('', encoding='utf-8')
    (project / 'app' / 'Http' / 'Controllers' / 'Demo.php').write_text(
        '<?php\nclass Demo {\n public function run($data) { eval($data); }\n}\n', encoding='utf-8')
    ui = StageTrackingUI(project, ai=ai)
    monkeypatch.setitem(sys.modules, 'streamlit', ui)
    monkeypatch.syspath_prepend(str(ROOT))
    import ollama_client
    import ai_engine
    monkeypatch.setattr(ollama_client, 'installed_models',
                        lambda: [SimpleNamespace(name='stub:latest')] if ai else [])
    model_calls = []

    def pretend_ollama(model, prompt, *, system, **kwargs):
        model_calls.append((system, prompt))
        if system == ai_engine.REVIEW_SYSTEM:
            yield json.dumps({'assessment': 'Potential use of dynamic code evaluation',
                              'verdict': 'needs_review', 'confidence': 'medium',
                              'rationale': 'Review data trust boundary', 'suggested_new_line': ''})
        else:
            yield '{"issues": []}'

    def pretend_stream(parts, **kwargs):
        from ai_engine import AIEvent
        for part in parts:
            yield AIEvent(kind='token', value=part, elapsed_seconds=0.1)

    monkeypatch.setattr(ai_engine, 'stream_ollama_json', pretend_ollama)
    monkeypatch.setattr(ai_engine, 'stream_with_heartbeat', pretend_stream)
    runpy.run_path(str(ROOT / 'app.py'), run_name='__main__')
    return ui, model_calls


def test_python_results_are_visible_before_ollama_starts(monkeypatch, tmp_path):
    ui, calls = run_two_stage(monkeypatch, tmp_path, ai=True)
    assert len(calls) >= 1
    statuses = [e[1] for e in ui.events if e[0] == 'status']
    assert len(statuses) == 2
    assert 'Stage 1' in statuses[0] and 'Python' in statuses[0]
    assert 'Stage 2' in statuses[1] and 'Ollama' in statuses[1]
    assert ui.status_depths == [0, 0], 'Both stages must use the full page width'
    assert any(e[0] == 'python-summary' and '1 potential security' in e[1] for e in ui.events)
    first_findings = next(i for i, e in enumerate(ui.events) if e[0] == 'table')
    stage_two = next(i for i, e in enumerate(ui.events) if e[0] == 'status' and 'Stage 2' in e[1])
    assert first_findings < stage_two, 'Python evidence should appear before Ollama work'
    record = ui.session_state['scan_result']
    assert len(record['result'].findings) == 1
    assert len(record['reviews']) == 1
    assert record['use_ai'] is True
    assert not record['failures']


def test_python_only_scan_never_calls_ollama(monkeypatch, tmp_path):
    ui, calls = run_two_stage(monkeypatch, tmp_path, ai=False)
    assert not calls
    assert len([e for e in ui.events if e[0] == 'status']) == 1
    record = ui.session_state['scan_result']
    assert record['use_ai'] is False
    assert len(record['result'].findings) == 1
    assert not record['reviews']
