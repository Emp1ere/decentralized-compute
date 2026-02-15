import logging
import os
import signal
import threading
import time
import tkinter as tk
from logging.handlers import RotatingFileHandler
from tkinter import ttk

from agent import DesktopAgent
from api import ApiClient
from config import (
    read_settings,
    write_settings,
    validate_client_id,
    validate_device_id,
    validate_hhmm,
    validate_url,
)


APP_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(APP_DIR, "agent.log")


def setup_logger():
    logger = logging.getLogger("desktop-agent-ui")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger
    handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", "%Y-%m-%d %H:%M:%S")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


class DesktopApp:
    def __init__(self, root):
        self.root = root
        self.logger = setup_logger()
        self.root.title("Distributed Compute Desktop Agent")
        self.agent = DesktopAgent(self._log)
        self.contracts_cache = []
        self.shutdown_lock = threading.Lock()
        self._build_ui()
        self._load_saved()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        try:
            signal.signal(signal.SIGINT, lambda *_: self._on_close())
            signal.signal(signal.SIGTERM, lambda *_: self._on_close())
        except (ValueError, AttributeError):
            pass

    def _build_ui(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.grid(sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        for i in range(2):
            frame.columnconfigure(i, weight=1)

        self.base_url = tk.StringVar(value="http://localhost:8080")
        self.api_key = tk.StringVar()
        self.client_id = tk.StringVar()
        self.verify_ssl = tk.BooleanVar(value=True)
        self.sector_var = tk.StringVar()
        self.contract_var = tk.StringVar()
        self.start_time = tk.StringVar(value="22:00")
        self.end_time = tk.StringVar(value="07:00")
        self.auto_next = tk.BooleanVar(value=True)
        self.check_updates = tk.BooleanVar(value=True)
        self.throttle_percent = tk.IntVar(value=0)
        self.device_id = tk.StringVar(value=f"dev-{int(time.time())}")
        self.device_name = tk.StringVar(value="Desktop agent")

        ttk.Label(frame, text="URL оркестратора").grid(row=0, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.base_url).grid(row=1, column=0, sticky="ew", padx=(0, 8))
        ttk.Label(frame, text="API ключ вычислителя").grid(row=0, column=1, sticky="w")
        ttk.Entry(frame, textvariable=self.api_key, show="*").grid(row=1, column=1, sticky="ew")

        ttk.Label(frame, text="Client ID").grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frame, textvariable=self.client_id).grid(row=3, column=0, sticky="ew", padx=(0, 8))
        ttk.Checkbutton(frame, text="Проверять SSL", variable=self.verify_ssl).grid(row=3, column=1, sticky="w")

        ttk.Label(frame, text="Device ID").grid(row=4, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frame, textvariable=self.device_id).grid(row=5, column=0, sticky="ew", padx=(0, 8))
        ttk.Label(frame, text="Device name").grid(row=4, column=1, sticky="w", pady=(8, 0))
        ttk.Entry(frame, textvariable=self.device_name).grid(row=5, column=1, sticky="ew")

        ttk.Button(frame, text="Проверить /me", command=self._check_me).grid(row=6, column=0, sticky="ew", pady=(8, 0))
        ttk.Button(frame, text="Обновить секторы/контракты", command=self._load_catalog).grid(row=6, column=1, sticky="ew", pady=(8, 0))

        ttk.Label(frame, text="Сектор").grid(row=7, column=0, sticky="w", pady=(8, 0))
        self.sector_combo = ttk.Combobox(frame, textvariable=self.sector_var, state="readonly")
        self.sector_combo.grid(row=8, column=0, sticky="ew", padx=(0, 8))
        self.sector_combo.bind("<<ComboboxSelected>>", lambda _e: self._apply_contract_filter())

        ttk.Label(frame, text="Контракт").grid(row=7, column=1, sticky="w", pady=(8, 0))
        self.contract_combo = ttk.Combobox(frame, textvariable=self.contract_var, state="readonly")
        self.contract_combo.grid(row=8, column=1, sticky="ew")

        ttk.Label(frame, text="Окно работы (HH:MM)").grid(row=9, column=0, sticky="w", pady=(8, 0))
        time_row = ttk.Frame(frame)
        time_row.grid(row=10, column=0, sticky="w")
        ttk.Entry(time_row, width=8, textvariable=self.start_time).pack(side=tk.LEFT)
        ttk.Label(time_row, text=" - ").pack(side=tk.LEFT)
        ttk.Entry(time_row, width=8, textvariable=self.end_time).pack(side=tk.LEFT)

        controls_row = ttk.Frame(frame)
        controls_row.grid(row=10, column=1, sticky="w")
        ttk.Checkbutton(controls_row, text="Авто-следующая часть", variable=self.auto_next).pack(anchor="w")
        ttk.Checkbutton(controls_row, text="Проверять обновления", variable=self.check_updates).pack(anchor="w")
        ttk.Label(controls_row, text="CPU throttle % (0..95)").pack(anchor="w")
        ttk.Entry(controls_row, width=10, textvariable=self.throttle_percent).pack(anchor="w")

        controls = ttk.Frame(frame)
        controls.grid(row=11, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        controls.columnconfigure(0, weight=1)
        controls.columnconfigure(1, weight=1)
        ttk.Button(controls, text="Старт", command=self._start_agent).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ttk.Button(controls, text="Стоп", command=self._stop_agent).grid(row=0, column=1, sticky="ew", padx=(4, 0))

        self.log_text = tk.Text(frame, height=18, wrap="word")
        self.log_text.grid(row=12, column=0, columnspan=2, sticky="nsew", pady=(10, 0))
        frame.rowconfigure(12, weight=1)

    def _log(self, message):
        ts = time.strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{ts}] {message}\n")
        self.log_text.see("end")
        self.logger.info(message)

    def _settings_payload(self):
        return {
            "base_url": self.base_url.get().strip(),
            "api_key": self.api_key.get().strip(),
            "client_id": self.client_id.get().strip(),
            "verify_ssl": bool(self.verify_ssl.get()),
            "start_time": self.start_time.get().strip(),
            "end_time": self.end_time.get().strip(),
            "auto_next": bool(self.auto_next.get()),
            "check_updates": bool(self.check_updates.get()),
            "throttle_percent": max(0, min(95, int(self.throttle_percent.get() or 0))),
            "device_id": self.device_id.get().strip(),
            "device_name": self.device_name.get().strip() or "Desktop agent",
            "sector_id": self.sector_var.get().split(" | ")[0] if self.sector_var.get() else "",
            "contract_id": self.contract_var.get().split(" | ")[0] if self.contract_var.get() else "",
        }

    def _load_saved(self):
        cfg = read_settings()
        self.base_url.set(cfg.get("base_url", self.base_url.get()))
        self.api_key.set(cfg.get("api_key", ""))
        self.client_id.set(cfg.get("client_id", ""))
        self.verify_ssl.set(bool(cfg.get("verify_ssl", True)))
        self.start_time.set(cfg.get("start_time", "22:00"))
        self.end_time.set(cfg.get("end_time", "07:00"))
        self.auto_next.set(bool(cfg.get("auto_next", True)))
        self.check_updates.set(bool(cfg.get("check_updates", True)))
        self.throttle_percent.set(int(cfg.get("throttle_percent", 0) or 0))
        self.device_id.set((cfg.get("device_id") or self.device_id.get()).strip())
        self.device_name.set((cfg.get("device_name") or "Desktop agent").strip())

    def _validate_inputs(self):
        if not validate_url(self.base_url.get()):
            return "Некорректный URL оркестратора."
        if not validate_client_id(self.client_id.get()):
            return "Некорректный client_id (ожидается UUID)."
        if not validate_device_id(self.device_id.get()):
            return "Некорректный device_id (3-128 символов: буквы/цифры/-/_/.)"
        if not validate_hhmm(self.start_time.get()) or not validate_hhmm(self.end_time.get()):
            return "Некорректный формат времени, используйте HH:MM."
        if not self.verify_ssl.get():
            self._log("ВНИМАНИЕ: SSL-проверка отключена.")
        return None

    def _check_me(self):
        validation_err = self._validate_inputs()
        if validation_err:
            self._log(validation_err)
            return
        try:
            api = ApiClient(self.base_url.get().strip(), self.api_key.get().strip(), self.verify_ssl.get())
            me = api.request("GET", "/me")
            self.client_id.set(me.get("client_id", self.client_id.get().strip()))
            rec = api.request(
                "POST",
                "/agent/devices/register",
                payload={
                    "device_id": self.device_id.get().strip(),
                    "device_name": self.device_name.get().strip() or "Desktop agent",
                    "agent_version": "0.3.0",
                },
            )
            self.device_id.set(rec.get("device_id", self.device_id.get().strip()))
            self._log(f"OK /me: {me.get('client_id', '')[:8]}..., balance={me.get('balance', 0)}")
            write_settings(self._settings_payload())
        except Exception as exc:
            self._log(f"Ошибка /me: {exc}")

    def _load_catalog(self):
        try:
            api = ApiClient(self.base_url.get().strip(), self.api_key.get().strip(), self.verify_ssl.get())
            contracts = api.public_get("/contracts")
            contracts = contracts if isinstance(contracts, list) else []
            self.contracts_cache = contracts
            sectors = {}
            for c in contracts:
                sector_id = c.get("sector_id") or ""
                sector_name = c.get("sector_name") or sector_id or "unknown"
                if sector_id:
                    sectors[sector_id] = sector_name
            options = [f"{sid} | {name}" for sid, name in sorted(sectors.items(), key=lambda x: x[1])]
            self.sector_combo["values"] = options
            if options and not self.sector_var.get():
                self.sector_var.set(options[0])
            self._apply_contract_filter()
            self._log(f"Каталог обновлён: contracts={len(contracts)}, sectors={len(options)}")
            write_settings(self._settings_payload())
        except Exception as exc:
            self._log(f"Ошибка загрузки каталога: {exc}")

    def _apply_contract_filter(self):
        selected = self.sector_var.get()
        selected_sector_id = selected.split(" | ")[0] if selected else ""
        options = []
        for c in self.contracts_cache:
            if selected_sector_id and c.get("sector_id") != selected_sector_id:
                continue
            options.append(f"{c.get('contract_id')} | {c.get('task_name', c.get('contract_id'))}")
        self.contract_combo["values"] = options
        if options and self.contract_var.get() not in options:
            self.contract_var.set(options[0])

    def _build_agent_cfg(self):
        sector_id = self.sector_var.get().split(" | ")[0] if self.sector_var.get() else ""
        contract_id = self.contract_var.get().split(" | ")[0] if self.contract_var.get() else ""
        return {
            "base_url": self.base_url.get().strip().rstrip("/"),
            "api_key": self.api_key.get().strip(),
            "client_id": self.client_id.get().strip(),
            "verify_ssl": bool(self.verify_ssl.get()),
            "sector_id": sector_id or None,
            "contract_id": contract_id or None,
            "start_time": self.start_time.get().strip(),
            "end_time": self.end_time.get().strip(),
            "auto_next": bool(self.auto_next.get()),
            "check_updates": bool(self.check_updates.get()),
            "throttle_percent": max(0, min(95, int(self.throttle_percent.get() or 0))),
            "device_id": self.device_id.get().strip(),
            "device_name": self.device_name.get().strip() or "Desktop agent",
        }

    def _start_agent(self):
        err = self._validate_inputs()
        if err:
            self._log(err)
            return
        cfg = self._build_agent_cfg()
        if not cfg["base_url"] or not cfg["api_key"] or not cfg["client_id"]:
            self._log("Нужно заполнить URL, API key и client_id.")
            return
        try:
            api = ApiClient(cfg["base_url"], cfg["api_key"], cfg["verify_ssl"])
            api.request(
                "POST",
                "/agent/devices/register",
                payload={
                    "device_id": cfg["device_id"],
                    "device_name": cfg["device_name"],
                    "agent_version": "0.3.0",
                },
            )
        except Exception as exc:
            self._log(f"Не удалось зарегистрировать устройство: {exc}")
            return
        write_settings(self._settings_payload())
        self.agent.start(cfg)

    def _stop_agent(self):
        self.agent.stop()

    def _on_close(self):
        with self.shutdown_lock:
            write_settings(self._settings_payload())
            if self.agent.is_running():
                self.agent.stop()
                self.root.after(300, self._final_close)
                return
            self._final_close()

    def _final_close(self):
        write_settings(self._settings_payload())
        self.root.destroy()


def main():
    root = tk.Tk()
    root.geometry("920x760")
    app = DesktopApp(root)
    app._log("Desktop Agent готов. Нажмите «Проверить /me» и «Обновить секторы/контракты».")
    root.mainloop()
