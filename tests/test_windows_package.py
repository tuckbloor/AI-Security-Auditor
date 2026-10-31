from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_starter_files_in_project_root():
    for filename in ("app.py", "README.md", "requirements.txt", "requirements-dev.txt",
                     "setup.bat", "run-app.bat", "run-tests.bat"):
        assert (ROOT / filename).is_file(), filename


def test_run_app_bootstraps_missing_environment():
    script = (ROOT / "run-app.bat").read_text(encoding="ascii").lower()
    assert 'call "%~dp0setup.bat"' in script
    assert "streamlit run" in script
    assert "missing virtual environment" not in script


def test_run_tests_bootstraps_missing_environment():
    script = (ROOT / "run-tests.bat").read_text(encoding="ascii").lower()
    assert 'call "%~dp0setup.bat"' in script
    assert "-m pytest -q" in script
    assert "missing virtual environment" not in script


def test_setup_creates_venv_and_installs_requirements():
    script = (ROOT / "setup.bat").read_text(encoding="ascii").lower()
    assert 'py -3.14 -m venv' in script
    assert 'pip install' in script
    assert 'requirements-dev.txt' in script
    assert '.security-auditor-v0.4.5-ready' in script
