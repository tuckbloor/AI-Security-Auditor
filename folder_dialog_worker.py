"""Small separate GUI process: Tk must not run in a Streamlit worker thread."""
import json


def main():
    root = None
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        root.update()
        selected = filedialog.askdirectory(
            parent=root,
            title='Select project folder to scan',
            mustexist=True,
        )
        print(json.dumps({'path': selected}))
    except Exception as error:
        print(json.dumps({'error': f'{type(error).__name__}: {error}'}))
        raise SystemExit(1)
    finally:
        if root is not None:
            root.destroy()


if __name__ == '__main__':
    main()
