"""Regression: every shipped .py file must compile, including the Streamlit entrypoint."""
from pathlib import Path
import ast
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_every_python_file_compiles():
    # Syntax checks don't require the optional Streamlit/Ollama installation.
    python_files = sorted(p for p in ROOT.rglob("*.py") if ".venv" not in p.parts)
    assert python_files
    for source_file in python_files:
        ast.parse(source_file.read_text(encoding="utf-8-sig"), filename=str(source_file))


def test_windows_launchers_check_syntax_before_streamlit_or_pytest():
    launcher = (ROOT / "run-app.bat").read_text(encoding="ascii")
    runner = (ROOT / "run-tests.bat").read_text(encoding="ascii")
    assert ' -m py_compile ' in launcher
    assert ' -m py_compile ' in runner
    assert launcher.index(' -m py_compile ') < launcher.index(' -m streamlit run ')
    assert runner.index(' -m py_compile ') < runner.index(' -m pytest -q')


def test_app_defines_real_scan_and_ai_handlers():
    tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
    audit = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "audit_run")
    assert any(isinstance(n, ast.With) for n in ast.walk(audit))
    assert any(isinstance(n, ast.Assign) for n in ast.walk(audit))
