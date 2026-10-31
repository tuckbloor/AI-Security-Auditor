import json
from types import SimpleNamespace
import pytest

import folder_picker


def test_browse_returns_selected_folder(monkeypatch, tmp_path):
    def fake_run(*args, **kwargs):
        assert kwargs['capture_output'] is True
        assert kwargs['check'] is False
        return SimpleNamespace(returncode=0, stdout=json.dumps({'path': str(tmp_path)}), stderr='')
    monkeypatch.setattr(folder_picker.subprocess, 'run', fake_run)
    assert folder_picker.browse_project_folder() == tmp_path.resolve()


def test_user_cancel_does_not_change_path(monkeypatch):
    monkeypatch.setattr(folder_picker.subprocess, 'run', lambda *a, **k:
                        SimpleNamespace(returncode=0, stdout='{"path":""}', stderr=''))
    assert folder_picker.browse_project_folder() is None


def test_nonexistent_folder_is_rejected(monkeypatch, tmp_path):
    missing = tmp_path / 'not-found'
    monkeypatch.setattr(folder_picker.subprocess, 'run', lambda *a, **k:
                        SimpleNamespace(returncode=0, stdout=json.dumps({'path': str(missing)}), stderr=''))
    with pytest.raises(RuntimeError, match='unavailable'):
        folder_picker.browse_project_folder()


def test_helper_failure_shows_error(monkeypatch):
    monkeypatch.setattr(folder_picker.subprocess, 'run', lambda *a, **k:
                        SimpleNamespace(returncode=1, stdout='{"error":"No GUI display"}', stderr=''))
    with pytest.raises(RuntimeError, match='No GUI display'):
        folder_picker.browse_project_folder()
