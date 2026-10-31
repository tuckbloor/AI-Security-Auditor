"""A native folder picker for a LOCAL Streamlit server on a desktop PC."""
from pathlib import Path
import json
import subprocess
import sys


def browse_project_folder(*, timeout=600):
    """Return an existing Path, or None when the dialog is cancelled."""
    helper = Path(__file__).with_name('folder_dialog_worker.py')
    try:
        proc = subprocess.run(
            [sys.executable, str(helper)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError('The folder selection timed out. Please try again.') from error
    except OSError as error:
        raise RuntimeError(f'Could not open the folder dialog: {error}') from error

    try:
        output = json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError) as error:
        raise RuntimeError('The folder picker did not return a valid selection. '
                           'Check that Tkinter is installed and the app is running on your desktop.') from error

    if proc.returncode or 'error' in output:
        raise RuntimeError(f"Windows folder picker failed: {output.get('error', proc.stderr.strip())}")
    raw = output.get('path', '')
    if not raw:
        return None  # user cancelled; keep previous folder
    folder = Path(raw).expanduser().resolve()
    if not folder.is_dir():
        raise RuntimeError(f'Selected project folder is unavailable: {folder}')
    return folder
