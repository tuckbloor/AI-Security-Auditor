"""Offline tests for the autonomous tool-calling security agent overlay."""
from __future__ import annotations

import json
import runpy
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from time import monotonic

import pytest

from agent_investigator import investigate_project
from agent_tools import ProjectTools, AgentToolError
from tests.test_one_progress_bar import ProgressUI
from tests.test_app_smoke import ROOT


def project_folder(tmp_path):
    root = tmp_path / 'project'
    (root / 'app' / 'Http' / 'Controllers').mkdir(parents=True)
    (root / 'routes').mkdir()
    (root / 'artisan').write_text('', encoding='utf-8')
    (root / 'app' / 'Http' / 'Controllers' / 'Demo.php').write_bytes(
        b'<?php\nclass Demo {\n public function run($data) { eval($data); }\n}\n')
    (root / 'routes' / 'web.php').write_bytes(b'<?php\nuse Illuminate\\Support\\Facades\\Route;\n')
    (root / '.env').write_text('SECRET_KEY=do_not_read', encoding='utf-8')
    return root


def tool_call(name, **kwargs):
    return {'function': {'name': name, 'arguments': kwargs}}


def fake_chat(responses):
    def chat(model, messages, **kwargs):
        result = responses.pop(0)
        yield {'message': result, 'done': True}
    return chat


def test_read_only_tools_search_and_read(tmp_path):
    root = project_folder(tmp_path)
    tool = ProjectTools(root)
    assert 'routes/web.php' in tool.execute('list_files', {'prefix': 'routes'})['files']
    matches = tool.execute('search_code', {'term': 'eval('})['matches']
    assert matches[0]['line'] == 3
    lines = tool.execute('read_file', {'path': 'app/Http/Controllers/Demo.php',
                                      'start_line': 2, 'end_line': 4})['lines']
    assert any('3: ' in x for x in lines)
    assert tool.execute('report_finding', {'path': 'app/Http/Controllers/Demo.php',
        'line': 3, 'severity': 'HIGH', 'category': 'Code execution',
        'explanation': 'This source uses eval with an unknown input boundary'})['accepted']


def test_rejects_outside_project_secrets_and_unread_evidence(tmp_path):
    root = project_folder(tmp_path)
    t = ProjectTools(root)
    for path in ('../hidden.py', '.env', '/etc/passwd', 'vendor/package/foo.php',
                 'app/Http/Controllers/none.php'):
        with pytest.raises(AgentToolError):
            t.read_file(path)
    with pytest.raises(AgentToolError):
        t.report_finding('app/Http/Controllers/Demo.php', 3, 'HIGH', 'Injection', 'unverified security issue')
    with pytest.raises(AgentToolError):
        t.execute('run_shell', {'cmd': 'dir'})
    assert (root / '.env').read_text() == 'SECRET_KEY=do_not_read'


def test_rejects_symlink_outside_project(tmp_path):
    root = project_folder(tmp_path)
    outside = tmp_path / 'outside.php'
    outside.write_text('<?php echo "secret";', encoding='utf-8')
    link = root / 'external.php'
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip('Symlink creation not enabled for this user')
    with pytest.raises(AgentToolError):
        ProjectTools(root).read_file('external.php')


def test_tool_call_loop_reads_file_then_returns_grounded_verdict(tmp_path):
    root = project_folder(tmp_path)
    lead = SimpleNamespace(path='app/Http/Controllers/Demo.php', line=3,
                           rule='Dynamic code evaluation', severity='HIGH', advice='Avoid eval')
    responses = [
        {'role': 'assistant', 'content': '', 'tool_calls': [
            tool_call('read_file', path=lead.path, start_line=1, end_line=4)]},
        {'role': 'assistant', 'content': '', 'tool_calls': [
            tool_call('search_code', term='Demo') ]},
        {'role': 'assistant', 'content': json.dumps({
            'assessment': 'Dynamic execution needs a trust boundary review',
            'verdict': 'needs_review', 'confidence': 'medium',
            'rationale': 'I read the source and searched for related calls',
            'suggested_new_line': ''})},
    ]
    trace = []
    result = investigate_project(root, 'fake:model', finding=lead,
                                 deadline=monotonic()+10, steps_limit=6,
                                 chat_turn=fake_chat(responses), on_activity=trace.append)
    assert result.review['verdict'] == 'needs_review'
    assert result.tools_used == ['read_file', 'search_code']
    assert result.incomplete is False
    assert any('Agent using tool: read_file' in x for x in trace)
    assert result.steps == 3
    assert 'eval(' in (root / lead.path).read_text()


def test_model_without_tool_use_does_not_claim_completed_review(tmp_path):
    root = project_folder(tmp_path)
    lead = SimpleNamespace(path='app/Http/Controllers/Demo.php', line=3,
                           rule='Dynamic code evaluation', severity='HIGH', advice='Avoid eval')
    response = {'role': 'assistant', 'content': json.dumps({
        'assessment': 'Looks bad', 'verdict': 'likely_issue', 'confidence': 'high'})}
    result = investigate_project(root, 'fake', finding=lead, deadline=monotonic()+10,
                                 chat_turn=fake_chat([response]))
    assert result.incomplete and result.review is None


def test_agent_discovery_requires_actual_read_before_reporting(tmp_path):
    root = project_folder(tmp_path)
    file = 'app/Http/Controllers/Demo.php'
    responses = [
        {'role': 'assistant', 'content': '', 'tool_calls': [tool_call('list_files', prefix='app/')]},
        {'role': 'assistant', 'content': '', 'tool_calls': [tool_call('read_file', path=file,
                                                                     start_line=1, end_line=4)]},
        {'role': 'assistant', 'content': '', 'tool_calls': [tool_call('report_finding', path=file,
             line=3, severity='HIGH', category='Dynamic execution',
             explanation='Dynamic eval found on this specific inspected source line')]},
        {'role': 'assistant', 'content': json.dumps({
            'assessment': 'One suspicious line', 'verdict': 'needs_review', 'confidence': 'medium'})},
    ]
    result = investigate_project(root, 'fake', deadline=monotonic()+10,
                                 chat_turn=fake_chat(responses))
    assert not result.incomplete
    assert len(result.issues) == 1
    assert result.issues[0]['line'] == 3
    assert (root / file).read_text().count('eval(') == 1


def test_agent_mode_in_real_app_still_has_single_progress_bar(monkeypatch, tmp_path):
    project = project_folder(tmp_path)
    ui = ProgressUI(project, ai=True)
    original_toggle = ui.toggle

    def toggle(label, **kwargs):
        if 'Autonomous AI security agent' in label:
            return True
        return original_toggle(label, **kwargs)
    ui.toggle = toggle
    monkeypatch.setitem(sys.modules, 'streamlit', ui)
    monkeypatch.syspath_prepend(str(ROOT))
    import ollama_client
    import agent_investigator
    from agent_investigator import InvestigationResult
    monkeypatch.setattr(ollama_client, 'installed_models', lambda: [SimpleNamespace(name='stub:latest')])
    calls = []
    def fake_agent(root, model, **kwargs):
        calls.append(kwargs.get('finding'))
        return InvestigationResult(
            {'assessment': 'Needs further review', 'verdict': 'needs_review',
             'confidence': 'low', 'rationale': 'Read source', 'suggested_new_line': ''}
            if kwargs.get('finding') else None,
            [], ['read_file'], 2, False, 'Completed')
    monkeypatch.setattr(agent_investigator, 'investigate_project', fake_agent)
    runpy.run_path(str(ROOT / 'app.py'), run_name='__main__')
    assert calls and calls[0] is not None
    assert ui.progress_calls == [(0.0, 0)]
    assert ui.progress_updates[-1][0] == 1.0
    assert ui.session_state.scan_result['agent_mode'] is True
    assert len(ui.session_state.scan_result['reviews']) == 1


def test_streamed_ollama_tool_response_protocol():
    from agent_investigator import stream_chat_turn
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def raise_for_status(self): pass
        def iter_lines(self):
            yield json.dumps({'message': {'role': 'assistant', 'content': '',
                'tool_calls': [tool_call('list_files', prefix='routes/')]}, 'done': False}).encode()
            yield json.dumps({'done': True, 'message': {'content': ''}}).encode()
    class Session:
        def post(self, url, **kwargs):
            assert url.endswith('/api/chat')
            assert kwargs['json']['tools']
            assert kwargs['json']['stream'] is True
            return Response()
    parts = list(stream_chat_turn('test', [{'role':'user','content':'Inspect files'}],
                                  timeout=5, inactivity=2, session=Session()))
    assert parts[0]['message']['tool_calls'][0]['function']['name'] == 'list_files'
    assert parts[-1]['done'] is True


def test_model_can_send_tool_request_as_plain_json(tmp_path):
    root = project_folder(tmp_path)
    file = 'app/Http/Controllers/Demo.php'
    calls = [
        {'role': 'assistant', 'content': json.dumps({'name': 'read_file',
                            'arguments': {'path': file, 'start_line': 1, 'end_line': 4}})},
        {'role': 'assistant', 'content': json.dumps({'assessment': 'Suspicious dynamic evaluation',
                    'verdict':'needs_review', 'confidence':'medium', 'rationale':'Source inspected'})},
    ]
    finding = SimpleNamespace(path=file, line=3, rule='Dynamic evaluation',
                              severity='HIGH', advice='Avoid eval')
    result = investigate_project(root, 'test', finding=finding, deadline=monotonic()+10,
                                 chat_turn=fake_chat(calls))
    assert result.review is not None
    assert result.tools_used == ['read_file']
