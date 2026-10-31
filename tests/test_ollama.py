from types import SimpleNamespace
import json
import pytest
from ollama_client import installed_models, investigate, redact_secrets, OllamaError


class FakeResponse:
    def __init__(self, value): self.value = value
    def raise_for_status(self): pass
    def json(self): return self.value


class FakeSession:
    def __init__(self, model_response=None):
        self.last_payload = None
        self.model_response = model_response or {'assessment':'Possible XSS; inspect context',
                                                 'confidence':'medium', 'suggested_new_line':'safeLine();',
                                                 'rationale':'Replace unsafe sink'}
    def get(self, url, timeout):
        assert url == 'http://127.0.0.1:11434/api/tags'
        return FakeResponse({'models': [{'name':'qwen2.5-coder:3b', 'size':2_000_000_000}, {'name':'llama3.2:3b','size':1_000_000_000}]})
    def post(self, url, json, timeout):
        self.last_payload = json
        assert '127.0.0.1' in url
        return FakeResponse({'message':{'content': __import__('json').dumps(self.model_response)}})


def test_installed_model_discovery_sorted():
    models = installed_models(session=FakeSession())
    assert [m.name for m in models] == ['llama3.2:3b', 'qwen2.5-coder:3b']
    assert models[-1].size_gb == 2.0


def test_model_results_are_json_and_source_not_executed():
    session=FakeSession()
    result=investigate('llama3.2:3b',rule='XSS',category='XSS', severity='MEDIUM',path='a.php',line=4,advice='escape',snippet='4: evil',session=session)
    assert result['assessment']
    assert session.last_payload['model']=='llama3.2:3b'
    assert session.last_payload['format']=='json'


def test_secret_redaction():
    text='password = "supersecret"\napi_key = "123456789101"\nTOKEN=abcd123456\nsk-verylongandprivatekey'
    result = redact_secrets(text)
    for secret in ('supersecret','123456789101','abcd123456','sk-verylongandprivatekey'):
        assert secret not in result


def test_investigate_redacts_source_before_sending():
    s=FakeSession()
    investigate('m',rule='Secret',category='secret', severity='HIGH',path='x.py',line=1,
                advice='rotate',snippet='password="SECRET123456789"',session=s)
    assert 'SECRET123456789' not in s.last_payload['messages'][1]['content']


def test_ai_rejects_multiline_suggestion():
    s=FakeSession({'assessment':'Possible', 'suggested_new_line':'a\nb'})
    result = investigate('m',rule='a',category='b',severity='MEDIUM',path='x',line=1,
                         advice='inspect',snippet='abc',session=s)
    assert result['suggested_new_line'] == ''


def test_ai_requires_assessment():
    s=FakeSession({'suggested_new_line':'hello'})
    with pytest.raises(OllamaError,match='assessment'):
        investigate('m',rule='a',category='b',severity='MEDIUM',path='x',line=1,
                    advice='inspect',snippet='abc',session=s)
