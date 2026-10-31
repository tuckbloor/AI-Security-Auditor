"""Ollama streaming, memory bounded scanning and defensive audit tests."""
import json
import time
from pathlib import Path
import pytest

from auditor import scan_project_stream, scan_project
from ai_engine import (
    CodeChunk, AIEvent, iter_code_chunks, iter_priority_sources, parse_review,
    parse_discovery, related_laravel_routes, review_prompt, discovery_prompt,
    stream_ollama_json, stream_with_heartbeat,
)
from ollama_client import OllamaError


class FakeHTTPResponse:
    def __init__(self, parts, status=200):
        self.parts, self.status = parts, status
        self.exited = False
    def __enter__(self): return self
    def __exit__(self, *args): self.exited = True
    def raise_for_status(self):
        if self.status != 200: raise RuntimeError('bad status')
    def iter_lines(self):
        for part in self.parts:
            yield json.dumps(part).encode()


class FakeClient:
    def __init__(self, parts):
        self.response = FakeHTTPResponse(parts)
        self.payload = None
        self.timeout = None
    def post(self, url, json, stream, timeout):
        assert url == 'http://127.0.0.1:11434/api/chat'
        assert stream is True
        self.payload = json
        self.timeout = timeout
        return self.response


def test_scan_generator_reports_progress_and_result(tmp_path):
    (tmp_path/'a.py').write_text('eval(user_input)\n')
    events = list(scan_project_stream(tmp_path))
    assert events[0].kind == 'progress'
    assert events[-1].kind == 'complete'
    assert events[-1].result.scanned_files == 1
    assert events[-1].result.findings[0].rule == 'Dynamic code evaluation'


def test_generator_stream_preserves_file_limit(tmp_path):
    for i in range(7): (tmp_path/f'{i}.py').write_text('eval(data)\n')
    assert list(scan_project_stream(tmp_path, max_files=3))[-1].result.truncated
    assert scan_project(tmp_path, max_files=3).scanned_files == 3


def test_lazy_chunks_read_real_lines(tmp_path):
    (tmp_path/'app.py').write_text(''.join(f'print({i})\n' for i in range(120)))
    chunks = list(iter_code_chunks(tmp_path, max_files=1, max_chunks=4, chunk_lines=40))
    assert len(chunks) == 3
    assert [c.start for c in chunks] == [1, 41, 81]
    assert chunks[-1].end == 120
    assert '1: print(0)' in chunks[0].source


def test_chunks_limited_and_secrets_ignored(tmp_path):
    (tmp_path/'.env').write_text('password=SECRET\n')
    (tmp_path/'a.py').write_text('print("x")\n'*1000)
    chunks = list(iter_code_chunks(tmp_path, max_chunks=2, chunk_lines=20))
    assert len(chunks) == 2
    assert all(c.path == 'a.py' for c in chunks)


def test_chunk_handles_empty_and_long_lines(tmp_path):
    (tmp_path/'empty.py').write_text('')
    (tmp_path/'other.py').write_text('x'*12000+'\n')
    chunks = list(iter_code_chunks(tmp_path, max_chunks=8))
    assert all(len(c.source) < 1000 for c in chunks)
    assert any(c.path == 'other.py' for c in chunks)


def test_source_priority_routes_before_random_file(tmp_path):
    (tmp_path/'a.py').write_text('print(1)')
    routes = tmp_path/'routes';routes.mkdir()
    (routes/'web.php').write_text('<?php Route::get("/",fn()=>"");')
    assert next(iter_priority_sources(tmp_path)).name == 'web.php'


def test_related_routes_only_from_controller(tmp_path):
    folder = tmp_path/'routes';folder.mkdir()
    (folder/'web.php').write_text('Route::resource("work-orders", WorkOrderController::class);')
    ctx = related_laravel_routes(tmp_path, 'app/Http/Controllers/WorkOrderController.php')
    assert 'WorkOrderController' in ctx
    assert not related_laravel_routes(tmp_path, 'config/app.php')


def test_stream_model_parts_and_done():
    client = FakeClient([
        {'message': {'content': '{"assessment":"'}},
        {'message': {'content': 'possible"}'}, 'done': True},
    ])
    parts = list(stream_ollama_json('small', {'source':'test'}, system='review',
                                    timeout_seconds=100, session=client))
    assert ''.join(parts) == '{"assessment":"possible"}'
    assert client.response.exited
    assert client.payload['stream'] is True
    assert client.payload['format'] == 'json'
    assert client.timeout[1] == 100


def test_stream_missing_done_raises():
    client = FakeClient([{'message': {'content': '{}'}}])
    with pytest.raises(OllamaError, match='completion'):
        list(stream_ollama_json('m', {}, system='x', timeout_seconds=100, session=client))


def test_stream_error_from_model():
    client = FakeClient([{'error': 'model unavailable', 'done': True}])
    with pytest.raises(OllamaError, match='unavailable'):
        list(stream_ollama_json('m', {}, system='x', timeout_seconds=100, session=client))


def test_stream_size_limit():
    client = FakeClient([{'message': {'content':'X'*33000}, 'done':True}])
    with pytest.raises(OllamaError, match='size limit'):
        list(stream_ollama_json('m', {}, system='x', timeout_seconds=100, session=client))


def test_stream_request_rejects_expired_budget():
    with pytest.raises(TimeoutError):
        list(stream_ollama_json('m', {}, system='x', timeout_seconds=0))


def test_stream_stall_timeout_is_configurable():
    client = FakeClient([{'message': {'content':'{}'}, 'done':True}])
    list(stream_ollama_json('m', {}, system='x', timeout_seconds=3600,
                            inactivity_seconds=450, session=client))
    assert client.timeout[1] == 450


def test_heartbeat_yields_tokens_and_finish():
    events = list(stream_with_heartbeat(iter(['hello', 'world']), timeout_seconds=10))
    assert events[0].kind == 'waiting'
    assert ''.join(e.value for e in events if e.kind == 'token') == 'helloworld'
    assert events[-1].kind == 'complete'


def test_heartbeat_reports_waiting_when_slow():
    def slow():
        time.sleep(0.07)
        yield '{}'
    events = list(stream_with_heartbeat(slow(), heartbeat_seconds=0.01, timeout_seconds=2))
    assert 'heartbeat' in [e.kind for e in events]


def test_heartbeat_timeout_does_not_hang_ui():
    def stuck():
        time.sleep(0.1)
        yield '{}'
    with pytest.raises(TimeoutError, match='timed out'):
        list(stream_with_heartbeat(stuck(), heartbeat_seconds=0.005, timeout_seconds=0.02))


def test_heartbeat_worker_error_propagated():
    def broken():
        yield 'a'
        raise OllamaError('model failed')
    with pytest.raises(OllamaError, match='failed'):
        list(stream_with_heartbeat(broken(), timeout_seconds=3))


def test_review_json_validation():
    data = parse_review(json.dumps({'assessment': 'unsafe?', 'verdict': 'likely_false_positive',
                                    'confidence': 'high', 'suggested_new_line': 'new();'}))
    assert data['verdict'] == 'likely_false_positive'
    assert data['suggested_new_line'] == 'new();'
    assert parse_review('{"assessment":"possible", "suggested_new_line":"x\\ny"}')['suggested_new_line'] == ''
    with pytest.raises(OllamaError): parse_review('not-json')


def test_discovery_line_and_severity_validation():
    chunk = CodeChunk('app/a.py', 10, 20, '10: eval(x)')
    issues = parse_discovery(json.dumps({'issues': [
        {'line': 99, 'severity': 'HIGH', 'category': 'exec', 'explanation': 'imagined'},
        {'line': 10, 'severity': 'HIGH', 'category': 'eval', 'explanation': 'potential unsafe eval'},
        {'line': 11, 'severity': 'nonsense', 'category': 'other', 'explanation': 'potential'}
    ]}), chunk)
    assert len(issues) == 2
    assert issues[0]['path'] == 'app/a.py'
    assert issues[1]['severity'] == 'MEDIUM'
    assert all(issue['source'].startswith('AI-suspected') for issue in issues)


def test_discovery_malformed_rejected():
    with pytest.raises(OllamaError):
        parse_discovery('{"issues": "n/a"}', CodeChunk('a.py',1,2,'1: print(1)'))


def test_secret_redaction_in_prompt(tmp_path):
    (tmp_path/'app.py').write_text('password = "SECRET1234567"\neval(input())\n')
    finding = scan_project(tmp_path).findings[-1]
    prompt, _ = review_prompt(tmp_path, finding)
    assert 'SECRET1234567' not in json.dumps(prompt)


def test_discovery_prompt_contains_no_raw_secret_after_redaction():
    chunk=CodeChunk('a.py',1,1,'1: token="privatevalue12345"')
    prompt=discovery_prompt(chunk,['Python'])
    assert 'privatevalue12345' not in json.dumps(prompt)
