# -*- coding: utf-8 -*-
"""Проверка подключения и готовности ноды Proxmox.

Перенесено из proxmox_backup.py v5 без изменений. В v5 взаимодействие
с нодой идёт по SSH штатными утилитам ноды (qm/pct/vzdump/pvesm),
отдельного REST-клиента у программы нет — здесь размещены существующие
функции проверки доступа к ноде, которые выполняются перед любой работой.
"""

import logging

from common import BackupError, RemoteCommandError
from proxmox.ssh import ssh_run

LOG = logging.getLogger("pve-backup")


def test_connection(cfg):
    proxmox = cfg["proxmox"]
    rc, out = ssh_run(cfg, "true", check=False)
    if rc != 0:
        raise RemoteCommandError(
            f"не удалось подключиться по SSH к {proxmox['user']}@{proxmox['host']}:"
            f"{proxmox['port']}.\nПроверьте доступность ноды, ключ/пароль, "
            f"и что вход работает.\nВывод ssh: {out.strip()}"
        )


def check_prerequisites(cfg):
    """Проверяет наличие всех нужных утилит на ноде (qm, pct, vzdump, pvesm)."""
    missing = []
    for tool in ("qm", "pct", "vzdump", "pvesm"):
        rc, _ = ssh_run(cfg, f"command -v {tool}", check=False)
        if rc != 0:
            missing.append(tool)
    if missing:
        raise BackupError(
            "на ноде не найдены утилиты: " + ", ".join(missing)
            + " — это точно нода Proxmox VE?")
