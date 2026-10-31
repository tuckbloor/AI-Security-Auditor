# 🛡️ AI Security Auditor

**A local, AI-powered source-code security auditor and tool-using investigation agent, built with Python, Streamlit and optional Ollama.**

AI Security Auditor examines an existing software project in **two clearly separated stages**: the Python Security Scan identifies potential issues first, then an optional Ollama model can investigate those findings and look for additional concerns. With **Autonomous AI security agent (tool calling)** enabled, the model can **choose which read-only source-inspection tools to use**, investigate related files and use actual code evidence before giving a verdict.

The classic interface is preserved: **one full-width progress bar**, readable activity updates, a Browse button, findings and AI verdicts, highlighted source code, and human-reviewed fixes. This README documents **classic v0.4.5 with the Agent Overlay installed**.

> [!IMPORTANT]
> **Ollama is optional.** The **Python Security Scan** works without an AI model or powerful GPU. The **AI Deep Investigation and autonomous agent mode** need a running Ollama server and an installed model; **tool calling depends on model support and reliability**. Smaller models may fail to call tools correctly or return incomplete results. This is an *assisted review tool*, not a guarantee that code is secure.

## Screenshots

### 1. Security overview

![AI Security Auditor — project selection and security overview](images/security-overview.png)

The dashboard shows the selected project, detected technologies, files scanned, Python rule findings, Ollama reviews, AI-discovered leads, errors and elapsed time.

### 2. Findings and AI verdicts

![AI Security Auditor — findings and AI verdicts with severity filter](images/findings-and-verdicts.png)

Filter the findings by severity or search by file, category or AI verdict. Python findings remain visible whether Ollama has reviewed them or not.

### 3. Examine an individual finding and its highlighted code

![AI Security Auditor — highlighted source line and AI verdict](images/code-review-highlight.png)

**The dropdown in Section 5 is how you change which code issue you are reviewing.** The relevant source line is highlighted in amber, with its original file and line number.

---

## Features

- **Browse for a project:** Windows native folder-selection dialog — no need to type a path.
- **Framework awareness:** identifies common markers of Laravel, PHP/Composer, Vue/Node and Python projects.
- **Stage 1 — Python Security Scan:** runs local, rule-based checks without sending code to an AI model.
- **Stage 2 — AI Deep Investigation:** Ollama reviews Python findings and optionally examines further source chunks for possible missed issues.
- **Autonomous investigation mode:** enable **🧠 Autonomous AI security agent (tool calling)** to let the model choose read-only investigation tools, follow code references and decide whether more evidence is needed.
- **Four guarded agent tools:** `list_files`, `search_code`, `read_file` and `report_finding`; Python validates paths and reported source lines.
- **Tool activity and limits:** view tool use in **View recent audit activity**, set the maximum reasoning steps and review incomplete or failed investigations.
- **Installed model selection:** choose from the models available in your local Ollama installation; refresh after downloading a model.
- **Live feedback:** a single full-width audit progress bar, status messages, file activity, elapsed time and AI response feedback.
- **Long-scan controls:** configurable overall, per-request and model-inactivity timeouts, plus limits on AI review scope.
- **Findings dashboard:** severity filters, searchable results, and separate Python, Ollama-reviewed and AI-discovered findings.
- **Highlighted code viewer:** select a finding and see the exact reported line highlighted in the surrounding source.
- **Reviewed code changes:** where supported, the AI may suggest a **single-line** edit; it shows a diff and needs your approval before writing, with safeguards and backups.
- **JSON export:** download a report on demand. **There is no results database or automatically saved scan history.**

## How the audit works

```text
Select a project with Browse
          |
          v
Stage 1: Python Security Scan
  - Walks eligible source files with generators
  - Runs rule-based checks
  - Produces initial potential findings
          |
          v
Stage 2: AI Deep Investigation (optional; Ollama)
  - Agent mode ON: AI chooses source-reading/search tools
  - Agent mode OFF: previous fixed AI review workflow
  - Reviews Python findings and can look for extra issues
  - Reports evidence-based verdicts or incomplete work
          |
          v
Security overview -> Findings table -> Select a finding -> Highlighted code
```

**Stage 1 always runs first.** Ollama does not replace the Python checks. The stages are sequential, not two independent scans running at the same time. When you choose **Python scan only**, the scan finishes without Ollama.

Python findings and AI verdicts are *potential* issues. In particular, an AI verdict such as `likely_issue` is the model's opinion and **not proof** of exploitable code. Always review the actual data flow, validation, authorisation and surrounding code.

## New: autonomous AI security investigation agent

The Agent Overlay turns the optional second stage from a fixed sequence of model prompts into a **bounded agent loop**. Python still controls permissions and executes the tools, but **Ollama decides which tools to request, examines their results, and can choose further investigation steps**.

| Tool chosen by Ollama | What it actually does |
|---|---|
| `list_files` | Lists allowed source files in the selected project. |
| `search_code` | Searches permitted source files for a phrase and returns real file/line matches. |
| `read_file` | Reads a bounded range of real source lines to inspect evidence. |
| `report_finding` | Records an **AI-suspected** issue only after the agent has read its reported source line. |

For example, when the Python scanner flags a database query, the agent might read that method, search for the corresponding Laravel route, inspect nearby validation and authorisation checks, then deliver a verdict. **Those are possible agent-selected actions, not guaranteed steps on every scan.**

**Why this is an agent:** the AI model selects tools and adjusts what it investigates based on the information returned, instead of only answering a single pre-written prompt. The investigation is limited by configured step counts, timeouts, and allowed files; it is **not** an unrestricted autonomous developer.

### Enable or disable agent mode

1. Start Ollama and select an installed model from the **Installed Ollama model** dropdown in the left sidebar.
2. Switch **🧠 Autonomous AI security agent (tool calling)** **ON**. It is on by default in the Agent Overlay.
3. Set **Agent maximum reasoning steps per investigation** (default **6**; selectable range **2–16**). More steps may improve exploration but take longer.
4. Click **🔎 Start Python + Ollama audit**. The Python stage runs first, then the agent starts working.
5. Open **View recent audit activity** in the results to see messages such as **Agent reasoning**, **Agent using tool**, **Agent investigating Python lead** and **Agent looking for additional issues**.
6. In **4 · Findings and AI verdicts**, inspect Python findings, Ollama verdicts and additional AI-suspected leads. In **5 · Examine a finding**, change the code being reviewed using **🔽 Select a finding to inspect — click to expand**.

To return to the previous, non-agent Ollama review, switch **Autonomous AI security agent (tool calling)** **OFF** *before* starting the audit. For a lightweight scan without any AI, choose **Python scan only**. Neither alternative requires a new installation.

### What the agent cannot do

The agent's source-investigation tools are **read-only**. It **cannot** execute project code, use a terminal, browse arbitrary websites, modify or delete files, or automatically fix vulnerabilities. The application's older **single-line proposed fix** feature is separate and still needs explicit approval. The agent does not comprehensively review an entire repository unless the requested work actually fits within its limits.

The application validates allowed paths and reported line references, but this is **not a proof that a finding is exploitable**. A finding may remain *unreviewed*, *needs review* or *incomplete* when the model fails to call tools, returns malformed data, times out or reaches its configured limits. Do not interpret a lack of findings as a security clearance.

## System requirements

| Component | Requirement |
|---|---|
| Operating system | Windows 10/11 for the included `.bat` scripts and native folder picker |
| Python | Python 3.14 recommended; the setup script also attempts another installed Python 3 version |
| Browser | Modern web browser for the local Streamlit interface |
| Internet | Needed to download Python packages initially; needed to download an Ollama model if using AI |
| Ollama | **Optional** for Python-only scans; required for AI deep investigation |
| GPU | **Not required** for Python scanning. Ollama can run on the CPU but may be much slower. |
| RAM and disk | Depends on the model. Smaller models are more practical on limited hardware; leave room for the model and its working context. |

### Should I install Ollama?

**If your PC has modest specifications**, begin with **Python Security Scan only**. It uses ordinary Python checks and does not run a large language model.

**If your PC has enough RAM and processing capacity**, install Ollama and try a relatively small coding model, such as `qwen2.5-coder:3b`. The model download is approximately 1.9 GB; runtime RAM requirements will be higher and depend on context length and acceleration. A stronger/larger model may improve some explanations but will use more resources.

You do **not** need a high-end graphics card, but CPU-only AI scans on large projects can take a long time. Avoid running large models or large AI scan scopes if they make your computer unresponsive. The Python scanner is still available without Ollama.

Official resources: [Download Ollama for Windows](https://ollama.com/download/windows) · [Ollama Windows documentation](https://github.com/ollama/ollama/blob/main/docs/windows.mdx) · [Qwen2.5-Coder model sizes](https://ollama.com/library/qwen2.5-coder).

---

## Download and installation — Windows

### Option A: Download from GitHub (recommended)

1. Open the **AI-Security-Auditor** repository on GitHub.
2. Select the green **Code** button, then **Download ZIP**.
3. In Windows File Explorer, right-click the downloaded ZIP and choose **Extract All**.
4. Extract it to a folder on your PC, for example `E:\AI-Security-Auditor`. GitHub may initially name the extracted folder `AI-Security-Auditor-main`; either is fine.
5. Open PowerShell in the folder containing **`app.py`**, **`setup.bat`**, **`run-tests.bat`** and **`run-app.bat`**. Do not run the commands from the parent folder.

To obtain it using Git instead (once the repository has been published), use:

```powershell
cd E:\
git clone https://github.com/tuckbloor/AI-Security-Auditor.git
cd .\AI-Security-Auditor
```

**GitHub repository:** [tuckbloor/AI-Security-Auditor](https://github.com/tuckbloor/AI-Security-Auditor).

### Option B: Use the complete standalone application ZIP

If you obtained the separately distributed Windows application ZIP, it contains a top-level folder called **`01-security-auditor`**. Extract **into `E:\`** (not into another `01-security-auditor` folder). The application should then be located at:

```text
E:\01-security-auditor\app.py
E:\01-security-auditor\setup.bat
E:\01-security-auditor\run-tests.bat
E:\01-security-auditor\run-app.bat
```

For this standalone ZIP, start PowerShell with:

```powershell
cd E:\01-security-auditor
```

### Install Python

1. Install Python for Windows from [python.org](https://www.python.org/downloads/windows/) if it is not already installed.
2. Open PowerShell and verify Python is available:

```powershell
py --list
```

The batch scripts create a **local `.venv` automatically** if it is missing, and install the required packages. Do **not** manually copy a `.venv` from another computer; it is machine-specific.

### Run the tests

```powershell
.\run-tests.bat
```

The command sets up Python if necessary, checks source syntax and then runs pytest. The output reports passed, failed or errored tests. This checks the application code and does **not** scan an external project.

### Start the application

```powershell
.\run-app.bat
```

The launcher installs dependencies on first use, checks Python syntax and starts Streamlit. Open:

**http://127.0.0.1:8501**

Keep the PowerShell window open while using the application. To stop the app, press **Ctrl+C** in that window.

### Manual start (advanced)

If the environment has already been set up and you prefer a direct command:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1
```

---

## Optional: install and configure Ollama

### 1. Install Ollama

Download and install the Windows version from **https://ollama.com/download/windows**. Start Ollama on your computer and check the models installed:

```powershell
ollama list
```

### 2. Download an appropriately sized model

For a lighter local code-analysis model, try (check that your chosen model reliably supports tool calling if you want **Agent mode**):

```powershell
ollama pull qwen2.5-coder:3b
```

A larger model is optional if your hardware can comfortably support it. You can see available sizes in the [Ollama model library](https://ollama.com/library/qwen2.5-coder).

### 3. Confirm Ollama is available

Ollama normally runs a local API at `http://127.0.0.1:11434`. In PowerShell you can check:

```powershell
Invoke-RestMethod http://127.0.0.1:11434/api/tags
```

If Ollama is not running, launch the desktop application; `ollama serve` is an alternative when a server is not already active. Do not start a second server on the same port.

### 4. Select it inside AI Security Auditor

In the **left sidebar**:

1. Look under **AI configuration**.
2. Click **Refresh installed Ollama models**.
3. Open the **Installed Ollama model** dropdown.
4. Select your preferred installed model.
5. For agent investigations, ensure **🧠 Autonomous AI security agent (tool calling)** is enabled and set its reasoning-step limit.

If no model is detected, the **Python-only scan still works**. If your model does not follow tool calls reliably, turn agent mode off or use a more capable tool-capable model.

> [!NOTE]
> Ollama AI review sends relevant source excerpts to the **configured local Ollama endpoint**. The application is not designed to upload your entire project to an external cloud provider. Review local privacy policies and do not enable remote/cloud models for confidential code without authorization.

---

## Complete user guide

### Step 1 — Select the project

1. Open the application.
2. Find **1 · Select a project**.
3. Click **📁 Browse for project**.
4. In the Windows folder dialog, choose your existing project (for example a Laravel, Vue or Python repository).
5. Confirm the chosen folder is shown beside the Browse button.

The folder picker opens on the **computer running Streamlit**. If you host the application on a remote machine, it does not browse the remote browser user's Windows files.

### Step 2 — Choose scan mode and options

- **Python scan only:** best for a quick first check, low-resource PCs and computers without Ollama.
- **Python + Ollama audit (agent ON):** runs Python first, then the model chooses safe repository tools to investigate findings and possibly discover additional suspected issues.
- **Python + Ollama audit (agent OFF):** runs Python first, then uses the previous fixed Ollama review workflow without autonomous tool selection.

In the sidebar, adjust the **overall audit duration**, **per-AI-request timeout**, **inactivity timeout**, **maximum findings to investigate**, and **maximum source files/chunks for AI discovery**. In agent mode also set **Agent maximum reasoning steps per investigation**.

The app deliberately limits how much code is sent to the model at once. Increasing the scope can significantly lengthen an audit.

### Step 3 — Watch the live audit

The application displays **ONE overall full-width progress bar**, plus live stage and activity text. You can see whether it is performing the **Python Security Scan** or the **AI Deep Investigation** and whether model requests have timed out. In agent mode, activity messages also show the source-inspection tools selected by Ollama and the investigation steps.

The bar measures estimated progress through scheduled scan/review work; it is **not** a live measurement of a model's reasoning or guaranteed coverage. A tool-calling model can spend a long time on one finding. Check the activity log and timeouts rather than assuming the app has crashed.

Progress tracks completed file and AI-review work; it is not an exact forecast of how quickly a model will respond. A timeout or scope limit should be treated as **incomplete coverage**, not a successful security clearance.

### Step 4 — Understand the Security overview (Section 3)

When the scan has finished, **3 · Security overview** summarises:

| Field | Meaning |
|---|---|
| Files scanned | Source files examined by the Python scanner |
| Rule leads | Potential issues detected by Python patterns |
| AI reviews | Python findings that Ollama evaluated |
| AI new leads | Additional suspected issues suggested by Ollama; **not verified** |
| AI errors | Failed AI requests or validation issues |
| Elapsed | Time used by the audit |

Use **View recent audit activity** to expand the most recent file and model activity messages. In **agent mode**, this is where you can see which tools Ollama requested and how many steps were used. It shows operational activity, **not** private internal model reasoning.

### Step 5 — Review the findings table (Section 4)

Open **4 · Findings and AI verdicts**. It contains **all Python leads**, even if a finding was not reviewed by Ollama, along with any separate AI-discovered leads.

- Choose **All severities** to see everything, or use the severity dropdown to filter.
- Enter a filename or topic in **Search findings by file, category or verdict** to narrow the list.
- Look at **Showing X of Y findings** to understand whether filtering has hidden rows.
- Use **Show all findings / clear filters** to restore the full list.
- Inspect the **Origin**, **Severity**, **Category**, **File**, **Line** and **Status** columns.

**A row is a potential finding, not automatically a confirmed security vulnerability.**

### Step 6 — IMPORTANT: change the selected code finding (Section 5)

> [!IMPORTANT]
> **To review a different issue, go to `5 · Examine a finding`, find `🔽 Select a finding to inspect — click to expand`, and CLICK THE DROPDOWN.** This is how you switch between reported files, line numbers and suspected vulnerabilities. The findings table above is a summary; selecting a row in that table is **not** the same as switching the code review.

1. Scroll below Section 4 to **5 · Examine a finding**.
2. Look for the blue **👇 SELECT A FINDING** instruction banner.
3. Click the grey dropdown labelled **🔽 Select a finding to inspect — click to expand**.
4. Choose an entry such as `6. HIGH · Code injection — app/Services/Example.php:91`.
5. The source-code viewer updates to the selected **file and line**.
6. Look for the **amber-highlighted line** and **⚠ REPORTED LINE** marker.
7. Read the security explanation and, if available, the **Ollama verdict** below the highlighted code.
8. Reopen the **same dropdown** to select and inspect the next issue. Repeat for each finding you want to review.

![Example of the code-review dropdown and amber-highlighted reported line](images/code-review-highlight.png)

**Important example:** A static command such as `PRAGMA foreign_keys=OFF` passed to a database `exec()` method is not, by itself, proof of SQL injection. Look for user-controlled SQL strings and missing parameterisation before treating an AI verdict as a real security flaw. Ollama can misinterpret a code snippet.

### Step 7 — Review a suggested correction (if available)

For supported findings, Ollama may propose a **single-line** change. The application shows a before/after diff. **No source code should be changed until you explicitly approve the proposal.** The edit workflow checks the source state and creates a backup when applying an approved change.

This version does **not** perform arbitrary multi-file edits, run application tests, or guarantee that proposed changes fix the underlying security problem. Use version control and retest your application after changing code.

### Step 8 — Download findings (optional)

Click **Download full audit JSON** to save an export manually. The application does not create a scan-results database or automatically retain historical reports.

To start another scan, use **Browse for project** again, including if you want to reselect the same folder.

---

## Scope, accuracy and safety

- The tool performs **static source inspection**. It does not execute the selected project's application code.
- Known dependency vulnerabilities are **not comprehensively checked** in this release; consider dedicated dependency-audit tooling as well.
- Rule-based matches can produce **false positives**. Ollama can also misunderstand snippets or miss problems that span multiple files. Tool calls improve evidence gathering but do **not** make the model infallible.
- Agent-mode output is subject to maximum tool calls, step limits and per-request / overall timeouts. Invalid paths and unsupported tools are rejected; investigations can finish incomplete.
- AI discovery examines only the files and source chunks allowed by the configured limits. A scan does **not** certify an entire repository.
- Some directories are excluded by default, including dependencies, generated artifacts, `.env` files and test/demo code. You can opt into test/demo scanning.
- Project source may be confidential. Scan only projects you own or are authorised to inspect. If using a local model, keep the Ollama server appropriately secured.
- Treat any finding as a starting point for developer review, not a substitute for professional penetration testing or security assessment.

## Troubleshooting

| Problem | What to do |
|---|---|
| `run-app.bat` cannot be found | Open the directory containing `app.py`; confirm extraction did not create an extra nested folder. |
| Missing `.venv` | Run `run-app.bat` or `setup.bat` from the application directory. The setup script creates it automatically. |
| `py` or Python not found | Install Python for Windows, then check `py --list`. |
| Ollama models do not appear | Start Ollama, run `ollama list`, and select **Refresh installed Ollama models**. |
| AI stage takes too long | Try a smaller model, reduce maximum findings/source chunks and agent reasoning steps, and adjust the model timeouts. CPU-only inference can be slow. |
| Agent mode does not appear | Install the **Agent Overlay for classic v0.4.5**, replacing its specified files, and restart Streamlit. |
| Ollama does not call tools | Confirm agent mode is ON and try a model with reliable tool calling; a small model may only return an explanation or malformed tool output. |
| Agent investigation is incomplete | Open **View recent audit activity** and error details. Check step limits, timeouts and whether it read the reported source line. Do not treat an incomplete verdict as verified. |
| Only the Python stage runs | You may have chosen **Python scan only**, or Ollama may not be running. |
| No findings appear | Clear the severity and search filters. No findings does not prove the project is secure. |
| Code viewer shows another file | **Use the Section 5 `Select a finding` dropdown** to change which source line is being reviewed. |
| A test file is unreadable on Windows | Confirm it exists and is readable in Explorer; investigate the Windows file access issue rather than assuming all source tests passed. |
| Streamlit port is already in use | Stop the existing Streamlit process (`Ctrl+C`) or close the earlier PowerShell window. |

## Project structure

```text
AI-Security-Auditor/
├── app.py                 # Streamlit user interface
├── auditor.py             # Python security rules and source traversal
├── ai_engine.py           # AI prompts, chunking, streaming and validation
├── agent_investigator.py  # Bounded Ollama tool-calling investigation loop (overlay)
├── agent_tools.py         # Safe, read-only source investigation tools (overlay)
├── ollama_client.py       # Local Ollama connection and model listing
├── findings_view.py       # Finding rows, filters and highlighted code
├── reviewed_edits.py      # Reviewed edit proposals and backups
├── folder_picker.py       # Windows project folder selection
├── folder_dialog_worker.py
├── setup.bat              # Creates .venv and installs dependencies
├── run-app.bat            # Starts the Streamlit application
├── run-tests.bat          # Runs the automated tests
├── requirements.txt
├── requirements-dev.txt
├── tests/
├── sample-project/
├── images/
│   ├── security-overview.png
│   ├── findings-and-verdicts.png
│   └── code-review-highlight.png
└── README.md
```

## Development and testing

From the project root:

```powershell
.\run-tests.bat
```

The test suite covers Python scanning, the Ollama request/response workflow, **agent tool selection and path restrictions**, source redaction, findings rendering, code-edit safeguards and source syntax. Test coverage does not replace live Windows GUI and real-model testing.

### Update the GitHub README after installing the overlay

Place this `README.md` in the **root** of your existing `AI-Security-Auditor` repository. Keep your screenshots in the existing root `images/` directory with the filenames used above. From PowerShell inside the repository:

```powershell
git add README.md
git commit -m "Document autonomous security investigation agent"
git push
```

This updates documentation only. It does not modify application code or publish changes automatically.

## Further reading

- [Python downloads](https://www.python.org/downloads/)
- [Streamlit documentation](https://docs.streamlit.io/)
- [Ollama for Windows](https://ollama.com/download/windows)
- [Ollama model library](https://ollama.com/library)
- [OWASP](https://owasp.org/)

---

**AI Security Auditor is a development and educational security review tool. Security findings and AI assessments always require human verification.**
