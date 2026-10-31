"""AI Security Auditor v0.4.5 — original full-width layout, one progress bar."""
from __future__ import annotations

from collections import Counter, deque
from itertools import islice
from pathlib import Path
from html import escape
from time import monotonic
import json

import streamlit as st

from auditor import MAX_FINDINGS, SEVERITIES, findings_as_dicts, scan_project_stream, iter_candidate_sources
from ai_engine import (REVIEW_SYSTEM, DISCOVER_SYSTEM, discovery_prompt,
                       iter_code_chunks, parse_review, parse_discovery,
                       review_prompt, stream_ollama_json, stream_with_heartbeat)
from folder_picker import browse_project_folder
from ollama_client import installed_models, OllamaError, redact_secrets
from reviewed_edits import source_excerpt, make_proposal, apply_proposal
from findings_view import (ALL_SEVERITIES, build_findings_rows, filter_findings_rows,
                           render_highlighted_excerpt)

VERSION = '0.4.5'
st.set_page_config(page_title=f'AI Security Auditor v{VERSION}', layout='wide', page_icon='🛡️')
st.markdown('''<style>
.block-container {max-width: 100%; padding-top: 1.5rem; padding-left: 2.2rem; padding-right: 2.2rem;}
[data-testid="stMetric"] {background:rgba(128,128,128,.065); border-radius:10px; padding:12px;}
.audit-log {width:100%; max-height:360px; overflow-y:auto; border:1px solid rgba(128,128,128,.32);
  border-radius:10px; padding:16px 18px; background:rgba(128,128,128,.07);
  font: 14px/1.65 Consolas, 'Courier New', monospace; color:inherit;
  overflow-wrap:anywhere; word-break:break-word; white-space:pre-wrap;}
.audit-current {font-size: 1rem; overflow-wrap:anywhere;}

.source-lines {width:100%; max-height:520px; overflow:auto; border:1px solid rgba(128,128,128,.40);
  border-radius:10px; background:rgba(128,128,128,.065); padding:10px 0;
  font:14px/1.6 Consolas, 'Courier New', monospace;}
.source-line {display:flex; align-items:flex-start; min-width:max-content; padding:2px 12px;
  white-space:pre; color:inherit;}
.source-number {flex:0 0 58px; text-align:right; padding-right:16px;
  color:rgba(128,128,128,.95); user-select:none;}
.source-text {flex:0 1 auto;}
.source-target {background:rgba(245,158,11,.24); border-left:5px solid #f59e0b;
  padding-left:7px; font-weight:700;}
.source-target .source-number {color:inherit;}
.target-flag {flex:0 0 auto; margin-left:20px; margin-right:12px; color:#b45309;
  background:rgba(245,158,11,.18); border-radius:4px; padding:1px 6px; font-weight:800;}
.finding-picker-note {border-left:5px solid #2563eb; background:rgba(37,99,235,.09);
  padding:10px 14px; border-radius:7px; margin:10px 0;}
</style>''', unsafe_allow_html=True)
st.title('🛡️ AI Security Auditor')
st.caption(f'v{VERSION} · Stage 1: Python Security Scan · Stage 2: AI Deep Investigation · Reviewed fixes')
st.info('AI findings are **suspected issues**, not proven vulnerabilities. No project source is executed. AI reviews run against your local Ollama server.')

for key, default in [('selected_project', None), ('model_inventory', None), ('model_error', None), ('audit_started', False)]:
    if key not in st.session_state:
        st.session_state[key] = default


def render_audit_log(messages: list[str]) -> str:
    """Full-width, safely escaped, wrapping audit activity for Streamlit."""
    content = '\n'.join(escape(str(message)) for message in messages) or 'No audit activity yet.'
    return '<div class="audit-log">' + content + '</div>'


def refresh_models():
    try:
        st.session_state.model_inventory = installed_models()
        st.session_state.model_error = None
    except Exception as exc:
        st.session_state.model_inventory = []
        st.session_state.model_error = str(exc)


with st.sidebar:
    st.header('AI configuration')
    if st.session_state.model_inventory is None or st.button('↻ Refresh installed Ollama models'):
        refresh_models()
    inventory = st.session_state.model_inventory or []
    if inventory:
        selected_model = st.selectbox('Installed Ollama model', [m.name for m in inventory])
        st.caption('Local Ollama: 127.0.0.1:11434')
    else:
        selected_model = None
        st.warning('No Ollama model detected. Start Ollama and refresh. Rule scanning still works.')
        if st.session_state.model_error:
            with st.expander('Connection details'):
                st.code(st.session_state.model_error)
    st.divider()
    st.header('Timeouts and scope')
    total_minutes = st.number_input('Maximum AI audit duration (minutes)', 5, 240, 30, 5)
    request_minutes = st.number_input('Maximum per AI request (minutes)', 1, 60, 5, 1)
    inactivity_seconds = st.number_input('Maximum wait without an Ollama response (seconds)', 30, 600, 180, 30)
    st.caption('The app keeps showing a heartbeat while waiting. A stalled request stops after this inactivity limit.')
    max_ai_findings = st.number_input('Maximum findings to investigate with AI', 1, 2000, 100, 10)
    ai_discovery = st.checkbox('AI also examines source chunks for missed issues', value=True)
    max_discovery_files = st.number_input('Maximum source files for AI discovery', 1, 200, 12, 1,
                                          disabled=not ai_discovery)
    max_discovery_chunks = st.number_input('Maximum AI source chunks', 1, 500, 24, 5,
                                           disabled=not ai_discovery)
    st.divider()
    include_tests = st.checkbox('Include test and demo code', value=False)
    max_files = st.number_input('Maximum source files for rule scanning', 100, 20000, 4000, 100)
    st.caption('Avoids .env, dependencies and generated directories. More AI requests = longer audits.')

st.subheader('1 · Select a project')
left, right = st.columns([1, 4], vertical_alignment='center')
with left:
    if st.button('📁 Browse for project', use_container_width=True):
        try:
            selected_folder = browse_project_folder()
            if selected_folder:
                st.session_state.selected_project = str(selected_folder)
                for key in ('scan_result', 'pending_fix', 'last_result', 'audit_mode', 'audit_activity', 'finding_severity_filter', 'finding_search'):
                    st.session_state.pop(key, None)
                st.session_state.audit_started = False
        except RuntimeError as exc:
            st.error(f'Folder picker error: {exc}')
with right:
    project = st.session_state.selected_project
    if project:
        st.code(project, language=None)
    else:
        st.caption('Choose a folder using the Windows Browse dialog. You do not need to type the path.')


def audit_run(use_ai: bool):
    """Run Python checks first, show their results, then deepen the investigation with Ollama.

    Both stages render at page width, outside any button columns. Stage 1 gives
    concrete findings even on slow machines; Stage 2 shows Ollama activity and
    uses Python to validate structured responses without claiming exploitation.
    """
    start = monotonic()
    deadline = start + float(total_minutes) * 60
    events = deque(maxlen=30)
    reviews: dict[str, dict] = {}
    failures: list[dict] = []
    discovery: list[dict] = []
    reviewed = 0
    count_ai = 0
    limited = False
    scan_result = None
    # Exactly one visible progress bar for the ENTIRE audit. Never present
    # a completed 100% bar while Ollama is still working.
    audit_progress = st.progress(0.0, text='Stage 1 · Starting Python security scan')
    current_progress = 0.0

    def move_progress(value: float, label: str):
        nonlocal current_progress
        current_progress = max(current_progress, min(1.0, max(0.0, float(value))))
        audit_progress.progress(current_progress, text=label)

    def log_event(phase: str, info: str):
        events.appendleft(f'{phase}: {redact_secrets(info[:300])}')

    # Stage 1 uses Python generators and never waits for Ollama. Its results
    # stay visible below while Stage 2 makes potentially slow model requests.
    st.markdown('### Stage 1 of 2 · Python Security Scan')
    st.caption('Checking source files with Python security rules for suspicious patterns. '
               'This stage works without Ollama and does not execute project code.')
    with st.status('🔎 Stage 1 — Python scanning source code...', expanded=True) as python_status:
        python_current = st.empty()
        python_metrics = st.empty()
        python_activity = st.empty()
        # Count candidate paths with a generator; never materialise all filenames.
        try:
            candidate_count = sum(1 for _ in islice(
                iter_candidate_sources(project, include_test_files=include_tests), int(max_files)))
        except (OSError, ValueError) as exc:
            python_status.update(label='❌ Stage 1 — Unable to list project files', state='error')
            st.error(f'Cannot scan project files: {exc}')
            return
        log_event('Python Security Scan', 'Starting file-by-file inspection')
        try:
            for tick in scan_project_stream(project, max_files=int(max_files), include_test_files=include_tests,
                                            max_findings=MAX_FINDINGS):
                if tick.kind == 'complete':
                    scan_result = tick.result
                elif tick.scanned_files % 8 == 0 or tick.scanned_files == 1:
                    info = f'{tick.scanned_files} files checked · {tick.file}'
                    python_current.write(f'Currently checking: {redact_secrets(tick.file)}')
                    python_metrics.caption(f'Files checked: {tick.scanned_files} · '
                                           f'Elapsed: {int(monotonic()-start)}s · Ollama: not started')
                    log_event('Python checking files', info)
                    python_activity.markdown(render_audit_log(list(events)[:12]), unsafe_allow_html=True)
                    move_progress(0.35 * tick.scanned_files / max(1, candidate_count),
                                  f'Stage 1 · Python: {tick.scanned_files}/{candidate_count} files checked')
            if scan_result is None:
                raise RuntimeError('Python scanner did not return a final result.')
        except Exception as exc:
            log_event('Python scan failed', str(exc))
            python_status.update(label='❌ Stage 1 — Python scan failed', state='error', expanded=True)
            st.error(f'Scan failed: {exc}')
            move_progress(current_progress, 'Stage 1 · Python scan failed — partial progress')
            return
        move_progress(0.35 if use_ai and selected_model else 0.95,
                      f'Stage 1 complete · {scan_result.scanned_files} source files checked')
        python_metrics.caption(f'Files checked: {scan_result.scanned_files} · '
                               f'Potential issues: {len(scan_result.findings)} · '
                               f'Unreadable files: {scan_result.unreadable_files}')
        log_event('Python scan complete', f'{scan_result.scanned_files} files; '
                  f'{len(scan_result.findings)} potential findings')
        python_status.update(label=f'✅ Stage 1 — Python scan complete: '
                             f'{scan_result.scanned_files} files, '
                             f'{len(scan_result.findings)} potential findings',
                             state='complete', expanded=False)

    # Present *real Python results immediately*, before the first AI request.
    st.success(f'Python checked {scan_result.scanned_files} source files and identified '
               f'{len(scan_result.findings)} potential security findings.')
    with st.expander(f'🔎 Stage 1 findings — {len(scan_result.findings)} Python leads', expanded=False):
        if scan_result.findings:
            st.dataframe([{'Severity': finding.severity, 'Finding': finding.rule,
                           'File': finding.path, 'Line': finding.line}
                          for finding in scan_result.findings[:200]],
                         use_container_width=True, hide_index=True)
            if len(scan_result.findings) > 200:
                st.caption('First 200 leads shown here. All retained rule leads appear in the final table.')
            st.caption('These are rule-based leads, not confirmed vulnerabilities. '
                       'Ollama has not reviewed them yet.')
        else:
            st.info('The Python rules did not identify any issues in the scanned scope. '
                    'That does not guarantee the project is secure.')
    if scan_result.truncated:
        limited = True
        st.warning('Python scanning reached its configured file/finding limit. '
                   'Unexamined files are not considered safe.')

    if use_ai and selected_model:
        st.markdown('### Stage 2 of 2 · AI Deep Investigation')
        st.caption(f'Ollama ({selected_model}) is reviewing Python leads and, if enabled, '
                   'independently examining bounded source chunks. Python validates response '
                   'structure and source locations as results arrive.')
        with st.status('🧠 Stage 2 — Ollama investigating further...', expanded=True) as ai_status:
            move_progress(0.35, 'Stage 2 · Preparing Ollama investigation')
            ai_current = st.empty()
            ai_metrics = st.empty()
            ai_activity = st.empty()

            def update(step: str, info: str, ratio: float = 0):
                elapsed = int(monotonic() - start)
                ai_current.write(f'{step} — {redact_secrets(info[:300])}')
                ai_metrics.caption(f'Elapsed: {elapsed // 60}m {elapsed % 60}s · '
                                   f'Python leads: {len(scan_result.findings)} · '
                                   f'AI reviewed: {reviewed} · '
                                   f'AI-discovered leads: {len(discovery)} · '
                                   f'Errors/timeouts: {len(failures)}')
                log_event(step, info)
                ai_activity.markdown(render_audit_log(list(events)[:18]), unsafe_allow_html=True)
                # Map Ollama phase to 35–99% of the ONE overall audit bar.
                move_progress(0.35 + 0.64 * max(0.0, min(1.0, ratio)),
                              f'Stage 2 · {step} · {elapsed // 60}m {elapsed % 60}s')

            def call_model(prompt: dict, system: str, name: str, ratio: float):
                budget = min(float(request_minutes) * 60, deadline - monotonic())
                if budget <= 0:
                    raise TimeoutError('Overall audit time limit reached.')
                chunks = stream_ollama_json(selected_model, prompt, system=system,
                                            timeout_seconds=budget,
                                            inactivity_seconds=float(inactivity_seconds))
                response_parts = []
                size = 0
                last_update = monotonic()
                for ev in stream_with_heartbeat(chunks, timeout_seconds=budget):
                    if ev.kind == 'token':
                        size += len(ev.value)
                        response_parts.append(ev.value)
                    if ev.kind in ('heartbeat', 'waiting') or monotonic() - last_update >= 0.35:
                        update('Ollama investigating further', f'{name} · '
                               f'{int(ev.elapsed_seconds)}s · {size} response characters', ratio)
                        last_update = monotonic()
                return ''.join(response_parts)

            total = min(len(scan_result.findings), int(max_ai_findings))
            if len(scan_result.findings) > total:
                limited = True
            update('AI review starting', f'{total} Python leads queued for Ollama', 0.0)
            for index, finding in enumerate(scan_result.findings[:total], 1):
                if monotonic() >= deadline:
                    limited = True
                    failures.append({'path': '', 'reason': 'Overall audit timeout; remaining work unreviewed.'})
                    break
                name = f'{finding.path}:{finding.line} · lead {index}/{total}'
                update('Preparing AI review', name, 0.65 * (index-1) / max(1, total))
                try:
                    payload, source_hash = review_prompt(project, finding)
                    raw = call_model(payload, REVIEW_SYSTEM, name, 0.65 * index / max(1, total))
                    update('Python validating AI response', name, 0.65 * index / max(1, total))
                    review = parse_review(raw)
                    reviews[finding.id] = {'review': review, 'source_hash': source_hash, 'model': selected_model}
                    reviewed += 1
                    update('AI review recorded', name, 0.65 * index / max(1, total))
                except (OllamaError, TimeoutError, ValueError, OSError) as exc:
                    failures.append({'path': name, 'reason': str(exc)[:400]})
                    update('AI review failed (continuing)', f'{name} · {str(exc)[:100]}',
                           0.65 * index / max(1, total))
                    if 'Overall audit' in str(exc):
                        limited = True
                        break
            if ai_discovery and monotonic() < deadline:
                max_chunks = int(max_discovery_chunks)
                seen: set[str] = set()
                for index, chunk in enumerate(iter_code_chunks(project, max_files=int(max_discovery_files),
                                                               max_chunks=max_chunks,
                                                               include_test_files=include_tests), 1):
                    if monotonic() >= deadline:
                        limited = True
                        failures.append({'path': '', 'reason': 'Overall audit timeout; AI discovery incomplete.'})
                        break
                    name = f'{chunk.path}:{chunk.start}-{chunk.end} · chunk {index}/{max_chunks}'
                    update('AI investigating additional code', name, 0.65 + 0.34 * (index-1)/max_chunks)
                    try:
                        raw = call_model(discovery_prompt(chunk, scan_result.frameworks),
                                         DISCOVER_SYSTEM, name, 0.65 + 0.34 * index/max_chunks)
                        update('Python validating discovered locations', name,
                               0.65 + 0.34 * index/max_chunks)
                        for issue in parse_discovery(raw, chunk):
                            if issue['id'] not in seen:
                                discovery.append(issue)
                                seen.add(issue['id'])
                        count_ai += 1
                    except (OllamaError, TimeoutError, ValueError, OSError) as exc:
                        failures.append({'path': name, 'reason': str(exc)[:400]})
                        update('AI discovery failed (continuing)', f'{name} · {str(exc)[:100]}',
                               0.65 + 0.34 * index/max_chunks)
            elif ai_discovery:
                limited = True
            if (ai_discovery and
                    count_ai + sum('chunk ' in f['path'] for f in failures) >= int(max_discovery_chunks)):
                limited = True  # Chunk cap reached; some source may remain unexamined.
            if failures:
                ai_status.update(label='⚠️ Stage 2 — AI investigation ended with errors/timeouts',
                                 state='error', expanded=False)
            elif limited:
                ai_status.update(label='⚠️ Stage 2 — AI scope limit reached',
                                 state='complete', expanded=False)
            else:
                ai_status.update(label=f'✅ Stage 2 — Ollama reviewed {reviewed} findings and '
                                 f'{count_ai} source chunks', state='complete', expanded=False)
            update('AI investigation finished',
                   f'{reviewed} findings reviewed · {len(discovery)} additional AI leads', 1.0)
        st.caption('Stage 1 Python findings remain available above; final combined results are below.')
    else:
        st.info('Stage 2 — AI Deep Investigation was skipped (Python-only scan). '
                'Select an installed Ollama model and start an AI-driven audit to run both stages.')
        log_event('AI investigation skipped', 'Python-only scan selected')

    completed = not limited and not failures
    # Only show 100% when all requested processing has actually ended.
    move_progress(1.0, ('Audit completed · results below' if completed else
                        'Audit ended with limits/errors · review partial results'))
    st.session_state.scan_result = {
        'root': str(Path(project).resolve()), 'result': scan_result, 'reviews': reviews,
        'discovery': discovery, 'failures': failures, 'limited': limited, 'use_ai': use_ai,
        'model': selected_model if use_ai else None, 'seconds': round(monotonic() - start, 1),
        'ai_chunks': count_ai, 'finished': completed, 'activity': list(events),
    }
    st.session_state.pop('pending_fix', None)


# Declare scan actions in a temporary placeholder, but execute the audit AFTER
# leaving all columns. Running audit_run inside a column was the cause of the
# narrow live output in v0.4.1.
scan_action = None
if not st.session_state.audit_started:
    action_slot = st.empty()
    with action_slot.container():
        buttons = st.columns([1, 1, 3])
        with buttons[0]:
            if st.button('🔎 Start Python + Ollama audit', disabled=not project or not selected_model,
                         type='primary', use_container_width=True):
                scan_action = True
        with buttons[1]:
            if st.button('🔎 Python scan only', disabled=not project, use_container_width=True):
                scan_action = False
        with buttons[2]:
            st.caption('AI processes real excerpts. A running or completed audit hides scan actions '
                       'until you choose a project again.')
    if scan_action is not None:
        # Hide BOTH buttons as soon as a scan starts, including the grey rule-scan
        # button. Selecting a project again is how the user begins another audit.
        st.session_state.audit_started = True
        st.session_state.audit_mode = 'AI' if scan_action else 'Rules'
        action_slot.empty()
        st.subheader('2 · Security audit progress')
        audit_run(scan_action)  # Top-level, full-width — never inside st.columns.
else:
    st.caption('Scan controls are hidden for this project. Browse for a project again to start a new audit.')

record = st.session_state.get('scan_result')
if record and project and record['root'] == str(Path(project).resolve()):
    result = record['result']
    reviews = record['reviews']
    discovery = record['discovery']
    st.divider()
    st.subheader('3 · Security overview')
    st.caption('Detected technologies: ' + ' · '.join(result.frameworks))
    with st.expander('View recent audit activity', expanded=False):
        st.markdown(render_audit_log(record.get('activity', [])), unsafe_allow_html=True)
    counts = Counter(f.severity for f in result.findings)
    cards = st.columns(6)
    cards[0].metric('Files scanned', result.scanned_files)
    cards[1].metric('Rule leads', len(result.findings))
    cards[2].metric('AI reviews', len(reviews))
    cards[3].metric('AI new leads', len(discovery))
    cards[4].metric('AI errors', len(record['failures']))
    cards[5].metric('Elapsed', f"{record['seconds']:.0f}s")
    if record['limited'] or result.truncated:
        st.warning('Audit was limited by its configured scope, a file/chunk cap, or a timeout. '
                   'Files not examined by AI must NOT be considered safe.')
    if record['failures']:
        with st.expander(f"View {len(record['failures'])} error/timeout details"):
            st.dataframe(record['failures'], hide_index=True, use_container_width=True)
    if result.unreadable_files:
        st.warning(f'{result.unreadable_files} source files could not be read.')
    if record['use_ai']:
        st.write(f"**Ollama:** {record['model']} · "
                 f"{len(reviews)}/{len(result.findings)} rule findings reviewed · "
                 f"{record['ai_chunks']} source chunks analysed independently")
    st.caption('Rule severity counts: ' + ' · '.join(f'{level}: {counts[level]}' for level in SEVERITIES))
    if not result.findings and not discovery:
        st.success('No findings were returned within the examined scope. This does not prove security.')

    st.subheader('4 · Findings and AI verdicts')
    all_rows = build_findings_rows(result.findings, reviews, discovery)
    st.caption(f'{len(result.findings)} Python leads · {len(reviews)} Ollama reviews · '
               f'{len(discovery)} AI-discovered leads (unverified). '
               'Every Python lead remains listed even if Ollama has not reviewed it.')

    def reset_finding_filters():
        st.session_state.finding_severity_filter = ALL_SEVERITIES
        st.session_state.finding_search = ''

    if st.button('↺ Show all findings / clear filters', on_click=reset_finding_filters,
                 disabled=not all_rows):
        pass
    severity = st.selectbox('Filter findings by severity', [ALL_SEVERITIES, *SEVERITIES],
                            key='finding_severity_filter')
    search = st.text_input('Search findings by file, category or verdict',
                           placeholder='e.g. WorkOrderController, injection, review',
                           key='finding_search')
    rows = filter_findings_rows(all_rows, severity, search)
    st.markdown(f'**Showing {len(rows)} of {len(all_rows)} findings**')
    if rows:
        # Explicit columns and data ensure the table is visible even when some
        # entries have not received an AI verdict.
        st.dataframe([{k: row[k] for k in ('Origin', 'Severity', 'Category', 'File', 'Line', 'Status')}
                      for row in rows], use_container_width=True, hide_index=True)
    elif all_rows:
        st.warning('No findings match these filters. Click “Show all findings / clear filters” above '
                   'to restore the full list. No findings have been discarded.')
    else:
        st.info('No findings were reported within the scanned scope. This does not prove the project '
                'is secure. Check the file count, scan limits and unexamined files in the overview.')
    export_data = {'project': project, 'model': record['model'], 'complete': record['finished'],
                   'seconds': record['seconds'], 'frameworks': result.frameworks,
                   'rule_findings': findings_as_dicts(result.findings),
                   'ai_reviews': {k: v['review'] for k, v in reviews.items()},
                   'ai_discovered_unverified': discovery, 'errors': record['failures']}
    st.download_button('Download full audit JSON', json.dumps(export_data, indent=2).encode(),
                       file_name='security-audit.json', mime='application/json')

    if rows:
        st.subheader('5 · Examine a finding')
        st.markdown('<div class="finding-picker-note"><strong>👇 SELECT A FINDING</strong> — '
                    'click the dropdown below to open the list of reported issues and see the '
                    'highlighted source line.</div>', unsafe_allow_html=True)
        keys = {f"{i+1}. {r['Severity']} · {r['Category']} — {r['File']}:{r['Line']} ": r
                for i, r in enumerate(rows)}
        label = st.selectbox('🔽 Select a finding to inspect — click to expand',
                             list(keys), help='Choose a security lead. The reported source line '
                             'will be highlighted below.')
        active = keys[label]
        finding = next((f for f in result.findings if f.id == active['Key']), None)
        if finding:
            st.write(f'**{finding.rule}** · {finding.advice}')
            data = reviews.get(finding.id)
            try:
                excerpt, current_hash = source_excerpt(project, finding.path, finding.line, radius=10)
                st.markdown(f'**Source context — highlighted reported line {finding.line}**')
                st.markdown(render_highlighted_excerpt(excerpt, finding.line),
                            unsafe_allow_html=True)
            except Exception as exc:
                excerpt = None
                st.error(f'Could not inspect current source: {exc}')
            if data:
                review = data['review']
                st.markdown(f"**Ollama verdict:** {review['verdict'].replace('_', ' ')} · "
                            f"Confidence: {review['confidence']} (model opinion)")
                st.write(review['assessment'])
                if review['rationale']:
                    st.caption(review['rationale'])
                if review['suggested_new_line'] and excerpt is not None:
                    st.markdown('**Optional reviewed one-line change**')
                    if st.button('Preview suggested fix', key=f'preview-{finding.id}'):
                        try:
                            change = make_proposal(project, finding.path, finding.line,
                                                   review['suggested_new_line'])
                            if change.expected_hash != data['source_hash']:
                                raise ValueError('File changed since AI inspected it. Scan again.')
                            st.session_state.pending_fix = {'id': finding.id, 'change': change}
                        except Exception as exc:
                            st.error(f'No change prepared: {exc}')
                    pending = st.session_state.get('pending_fix')
                    if pending and pending['id'] == finding.id:
                        st.code(pending['change'].diff, language='diff')
                        approved = st.checkbox('I inspected this diff and approve writing to disk', key=f'approval-{finding.id}')
                        c1,c2 = st.columns(2)
                        if c1.button('Apply approved change', disabled=not approved, type='primary'):
                            try:
                                backup = apply_proposal(project, pending['change'],
                                                        Path.home()/'AI-Security-Auditor-Backups')
                                st.session_state.last_result = f'Verified file saved. Backup: {backup}'
                                st.session_state.pop('pending_fix', None)
                                st.session_state.pop('scan_result', None)
                                st.rerun()
                            except Exception as exc:
                                st.error(f'File NOT edited: {exc}')
                        if c2.button('Reject change'):
                            st.session_state.pop('pending_fix', None)
                            st.rerun()
                else:
                    st.caption('No one-line fix proposed. Some security fixes require multi-file changes.')
            else:
                st.info('This rule finding has not been investigated by Ollama.')
                if selected_model and excerpt is not None and st.button('Investigate this finding with Ollama'):
                    try:
                        payload, source_hash = review_prompt(project, finding)
                        with st.status('Ollama is examining this finding...', expanded=True) as progress_box:
                            activity = st.empty()
                            pieces = []
                            budget = request_minutes * 60
                            parts = stream_ollama_json(selected_model, payload, system=REVIEW_SYSTEM,
                                                       timeout_seconds=budget,
                                                       inactivity_seconds=float(inactivity_seconds))
                            for ev in stream_with_heartbeat(parts, timeout_seconds=budget):
                                if ev.kind == 'token':
                                    pieces.append(ev.value)
                                if ev.kind in {'heartbeat', 'token'}:
                                    activity.caption(f'Ollama running · {ev.elapsed_seconds:.0f}s elapsed · '
                                                     f'{sum(map(len,pieces))} characters received')
                            record['reviews'][finding.id] = {
                                'review': parse_review(''.join(pieces)),
                                'source_hash': source_hash, 'model': selected_model,
                            }
                            progress_box.update(label='AI investigation completed', state='complete')
                        st.rerun()
                    except (OllamaError, TimeoutError, ValueError, OSError) as exc:
                        st.error(f'Ollama investigation failed without modifying code: {exc}')
        else:
            issue = next((i for i in discovery if i['id'] == active['Key']), None)
            if issue:
                st.warning('AI-suspected issue: it has not been independently confirmed.')
                st.write(issue['assessment'])
                try:
                    snippet,_ = source_excerpt(project, issue['path'], issue['line'], radius=8)
                    st.markdown(f'**Source context — highlighted AI-reported line {issue["line"]}**')
                    st.markdown(render_highlighted_excerpt(snippet, issue['line']),
                                unsafe_allow_html=True)
                except Exception as exc:
                    st.error(f'Unable to verify source location: {exc}')

if st.session_state.get('last_result'):
    st.success(st.session_state.last_result)
    if st.button('Dismiss save confirmation'):
        st.session_state.pop('last_result', None)
        st.rerun()
st.divider()
st.caption('AI never runs project code. All source edits require explicit approval and create a backup. '
           'Only the local Ollama API receives bounded, redacted source excerpts.')
