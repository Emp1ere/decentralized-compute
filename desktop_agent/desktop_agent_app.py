import os
import sys
import traceback
from datetime import datetime


def _write_crash_log(error_text: str) -> str:
    app_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(app_dir, "desktop_agent_crash.log")
    with open(log_path, "a", encoding="utf-8") as fp:
        fp.write(f"\n=== {datetime.now().isoformat()} ===\n")
        fp.write(error_text)
        fp.write("\n")
    return log_path


def _show_crash_popup(log_path: str):
    message = (
        "Desktop Agent crashed during startup.\n\n"
        f"Crash log: {log_path}\n\n"
        "Please run start_desktop_agent.bat and share this log if issue persists."
    )
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Desktop Agent startup error", message)
        root.destroy()
    except Exception:
        # Fallback: keep at least console output for cmd launches.
        print(message)


if __name__ == "__main__":
    try:
        app_dir = os.path.dirname(os.path.abspath(__file__))
        if app_dir not in sys.path:
            sys.path.insert(0, app_dir)
        from ui import main

        main()
    except Exception:
        error_text = traceback.format_exc()
        crash_log = _write_crash_log(error_text)
        _show_crash_popup(crash_log)
