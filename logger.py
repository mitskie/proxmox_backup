# -*- coding: utf-8 -*-
"""Настройка логирования и вспомогательные функции форматирования сообщений.

Перенесено из proxmox_backup.py v5 без изменений: уровни логирования,
формат сообщений и правила вывода сохранены. Все модули проекта пишут
в один и тот же логгер «pve-backup» (logging.getLogger возвращает один
объект для одного имени), поэтому обработчики настраиваются здесь
один раз в setup_logging.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path


def _level(name, fallback):
    return getattr(logging, str(name).upper(), fallback)


def setup_logging(cfg, console_level):
    log_dir = Path(cfg["logging"]["dir"]).expanduser()
    log_dir.mkdir(parents=True, exist_ok=True)
    logfile = log_dir / f"backup_{datetime.now():%Y%m%d}.log"

    formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s",
                                  "%Y-%m-%d %H:%M:%S")
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers.clear()

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(console_level)
    console.setFormatter(formatter)
    root.addHandler(console)

    file_handler = logging.FileHandler(logfile, encoding="utf-8")
    file_handler.setLevel(_level(cfg["logging"]["file_level"], logging.DEBUG))
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)
    return logfile


def human_size(num):
    value = float(num)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if value < 1024 or unit == "ТБ":
            return f"{value:.1f} {unit}" if unit != "Б" else f"{int(value)} {unit}"
        value /= 1024
    return f"{value:.1f} ТБ"


def _plural(n, one, few, many):
    """Русская словоформа для числа n: 1 копия / 2 копии / 5 копий."""
    n = abs(int(n)) % 100
    if 11 <= n <= 14:
        return many
    n %= 10
    if n == 1:
        return one
    if 2 <= n <= 4:
        return few
    return many
