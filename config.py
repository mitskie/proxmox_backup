# -*- coding: utf-8 -*-
"""Загрузка и проверка конфигурации (Python-файл backup_config.py).

Перенесено из proxmox_backup.py v5 без изменений: имена параметров,
значения по умолчанию, обработка отсутствующих параметров и формат
конфигурационного файла сохранены.
"""

import importlib.util
import logging
from pathlib import Path

from common import BackupError
from logger import _level

MODES = ("snapshot", "suspend", "stop")
COMPRESSIONS = ("zstd", "gzip", "lzo", "none")

DEFAULT_PROXMOX = {"host": "", "port": 22, "user": "root",
                   "key_file": "", "password": "", "ssh_timeout": 0}
DEFAULT_BACKUP = {"storage": "local", "mode": "snapshot", "compress": "zstd",
                  "destination": "./backups", "delete_after_download": True}
DEFAULT_VMS = {"include": [], "exclude": []}
DEFAULT_LOGGING = {"dir": "./logs", "console_level": "INFO", "file_level": "DEBUG"}


def find_config(explicit):
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise BackupError(f"конфиг не найден: {path}")
        return path
    for candidate in (Path.cwd() / "backup_config.py",
                      Path(__file__).resolve().parent / "backup_config.py"):
        if candidate.is_file():
            return candidate
    raise BackupError(
        "не найден backup_config.py — задайте --config или положите конфиг "
        "в каталог запуска / рядом со скриптом (пример — backup_config.py)"
    )


def parse_vm_ids(values):
    """Список VMID из int/str (в т.ч. '100, 101') -> sorted set of int."""
    ids = []
    for value in values or []:
        for token in str(value).split(","):
            token = token.strip()
            if token:
                ids.append(int(token))
    return sorted(set(ids))


def load_config(path):
    """Исполняет Python-файл конфига и собирает проверенный словарь."""
    spec = importlib.util.spec_from_file_location("pve_backup_cfg", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    proxmox = {**DEFAULT_PROXMOX, **dict(getattr(module, "PROXMOX", {}) or {})}
    backup = {**DEFAULT_BACKUP, **dict(getattr(module, "BACKUP", {}) or {})}
    vms = {**DEFAULT_VMS, **dict(getattr(module, "VMS", {}) or {})}
    logg = {**DEFAULT_LOGGING, **dict(getattr(module, "LOGGING", {}) or {})}

    if not str(proxmox["host"]).strip():
        raise BackupError("в конфиге не задан PROXMOX['host'] (IP или имя ноды)")
    try:
        port = int(proxmox["port"])
        if not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        raise BackupError(f"некорректный PROXMOX['port']: {proxmox['port']!r}")
    proxmox["port"] = port
    try:
        timeout = int(proxmox.get("ssh_timeout", 0) or 0)
        if timeout < 0:
            raise ValueError
    except (TypeError, ValueError):
        raise BackupError(f"некорректный PROXMOX['ssh_timeout']: {proxmox['ssh_timeout']!r}")
    proxmox["ssh_timeout"] = timeout
    password = proxmox.get("password") or ""
    proxmox["password"] = str(password) if password else ""

    if backup["mode"] not in MODES:
        raise BackupError(f"недопустимый BACKUP['mode']: {backup['mode']!r} "
                          f"(разрешены: {', '.join(MODES)})")
    if backup["compress"] not in COMPRESSIONS:
        raise BackupError(f"недопустимый BACKUP['compress']: {backup['compress']!r} "
                          f"(разрешены: {', '.join(COMPRESSIONS)})")
    if not str(backup["storage"]).strip():
        raise BackupError("в конфиге не задан BACKUP['storage']")
    if not str(backup["destination"]).strip():
        raise BackupError("в конфиге не задан BACKUP['destination']")
    if not isinstance(backup["delete_after_download"], bool):
        raise BackupError(
            "BACKUP['delete_after_download'] должен быть True или False")

    try:
        vms["include"] = parse_vm_ids(vms["include"])
        vms["exclude"] = parse_vm_ids(vms["exclude"])
    except ValueError as exc:
        raise BackupError(f"VMS['include']/VMS['exclude'] должны быть числами: {exc}")

    _level(logg["console_level"], logging.INFO)
    _level(logg["file_level"], logging.DEBUG)

    return {"proxmox": proxmox, "backup": backup, "vms": vms, "logging": logg}
