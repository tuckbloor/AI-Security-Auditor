from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT/'app.py').read_text(encoding='utf-8')
README = (ROOT/'README.md').read_text(encoding='utf-8')


def test_visible_live_audit_and_browser():
    assert 'Browse for project' in APP
    assert 'Start Python + Ollama audit' in APP
    assert 'Installed Ollama model' in APP
    assert 'stream_with_heartbeat' in APP
    assert 'Maximum AI audit duration' in APP
    assert 'Maximum per AI request' in APP
    assert 'Maximum wait without an Ollama response' in APP


def test_results_distinguish_ai_from_rule_leads():
    assert 'AI discovered (unverified)' in (ROOT/'findings_view.py').read_text(encoding='utf-8')
    assert 'Not AI-reviewed' in (ROOT/'findings_view.py').read_text(encoding='utf-8')
    assert 'AI review failed (continuing)' in APP
    assert 'File NOT edited' in APP


def test_installer_readme_and_folder_consistency():
    assert '01-security-auditor' in README
    assert 'E:\\01-security-auditor' in README
    assert 'run-app.bat' in README
    assert 'run-tests.bat' in README
    for path in ['app.py', 'ai_engine.py', 'setup.bat', 'run-app.bat', 'run-tests.bat']:
        assert (ROOT/path).is_file()


def test_no_manual_venv_required():
    setup = (ROOT/'setup.bat').read_text(encoding='ascii')
    launcher = (ROOT/'run-app.bat').read_text(encoding='ascii')
    assert 'v0.4.5-ready' in setup
    assert 'setup.bat' in launcher
    assert '-m streamlit run' in launcher


def test_full_width_audit_workflow_and_visible_activity():
    assert "VERSION = '0.4.5'" in APP
    assert "action_slot.empty()" in APP
    assert "st.session_state.audit_started = True" in APP
    assert "st.session_state.audit_started = False" in APP
    assert "audit_run(scan_action)" in APP
    assert "render_audit_log" in APP
    assert 'overflow-wrap:anywhere' in APP
    assert "'activity': list(events)" in APP
    # Audit execution must be after (not nested in) the action button columns.
    assert APP.index('with buttons[2]:') < APP.index('audit_run(scan_action)')
