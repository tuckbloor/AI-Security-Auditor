# AI Security Auditor — Agent Overlay (for classic v0.4.5)

This is an **overlay**, not a new application. It converts the existing AI investigation into an optional **tool-using agent** while preserving the classic full-width layout, **ONE progress bar**, Browse button, installed Ollama model list, highlighted source lines, and reviewed fixes.

## 1. Install over the existing application

The ZIP contains **one folder named `01-security-auditor`**. Extract it to **`E:\`** and choose **Replace files** when asked. The existing application stays at:

`E:\01-security-auditor\app.py`

The overlay **replaces only** `app.py` and `run-app.bat`, and adds `agent_tools.py`, `agent_investigator.py`, this guide, and `tests/test_agent_overlay.py`. It does **not** replace your existing README, Python scanner, previous tests, images, or dependencies. Do not extract into `E:\01-security-auditor` or an extra nested folder will be created.

Before extracting, stop Streamlit with **Ctrl+C**. Prefer to commit your working project first with Git, so rollback is easy:

```powershell
cd E:\01-security-auditor
git status
git add .
git commit -m "Working security auditor before agent overlay"
```

If the project has uncommitted changes you don't want to commit, make a copy of `app.py` and `run-app.bat` first.

## 2. Start

```powershell
cd E:\01-security-auditor
.\run-app.bat
```

You do **not** need to recreate `.venv` or install new Python packages. Python scanning works without Ollama. For agent mode, Ollama must be running locally with an installed model that supports tool calling, e.g. `qwen2.5-coder:3b` (larger capable models generally perform better but need more RAM).

## 3. Use the agent

1. Click **Browse for project** and select your Laravel, Vue, or Python project.
2. In the left sidebar choose an **Installed Ollama model**.
3. Check that **🧠 Autonomous AI security agent (tool calling)** is ON (the default). Turn it off to use the old AI review flow.
4. Set **Agent maximum reasoning steps per investigation** (default 6), per-request and total audit timeouts, and how many findings to inspect.
5. Click **Start Python + Ollama audit**.
6. **Stage 1: Python Security Scan** runs first, then **Stage 2: AI Deep Investigation**. Ollama now chooses which read-only tools to call; the live activity says which tools are used. Both stages share the existing **single full-width progress bar**.
7. Under **Section 4 — Findings and AI verdicts**, see Python leads, AI verdicts and agent-discovered leads. Under **Section 5 — Examine a finding**, use the **Select a finding** dropdown to switch the highlighted source line.

The agent can choose among `list_files`, `search_code`, `read_file`, and `report_finding`. Results are only accepted if the referenced files and line numbers are real and read by the agent. It **cannot** run commands, execute scanned code, delete files, send emails or edit code autonomously. The existing **approved one-line fix** workflow is unchanged.

## 4. Model limitations

Small local models may fail to issue valid tool calls or may return malformed JSON. These are reported as incomplete investigations, **not verified findings**. Use another installed tool-capable model if necessary. Increasing maximum steps, request timeouts and findings investigated increases CPU/RAM use and runtime. The scan stays in memory; there is no database or automatic scan history.

## 5. Test only the overlay

```powershell
cd E:\01-security-auditor
.\run-tests.bat
```

If Windows reports a file-read error for an old unrelated test, you can run just the new overlay tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_agent_overlay.py
```

Use your existing virtual-environment Python for tests when it is present, or use `run-tests.bat` to create it automatically. The overlay was tested against the exact **v0.4.5 classic application source**. Live Ollama inference and the native Windows Streamlit UI still require verification on your PC.
