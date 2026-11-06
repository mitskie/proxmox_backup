# -*- coding: utf-8 -*-
"""Гости ноды Proxmox: ВМ (qemu) и LXC-контейнеры.

Перенесено из proxmox_backup.py v5 без изменений: получение списков
(qm list / pct list), разбор столбцов, включая пустые имена и столбец
Lock («-» означает отсутствие блокировки и в имя не попадает),
обработка идентификаторов и выбор целей по include/exclude.
"""

import logging

from common import BackupError
from proxmox.ssh import ssh_run

LOG = logging.getLogger("pve-backup")

# Статусы гостей и их блокировки в выводе qm list / pct list
KNOWN_STATUSES = {"running", "stopped", "paused"}
KNOWN_LOCKS = {"backup", "create", "copy", "migrate", "mounted",
               "restore", "rollback", "snapshot", "locked"}


def get_node_guests(cfg):
    """Список гостей: ВМ (qm list) + LXC-контейнеры (pct list).

    Если любая из команд недоступна — остановка: молча пропустить часть
    гостей нельзя, иначе бэкап был бы неполным.
    """
    guests = []
    rc, out = ssh_run(cfg, "qm list", check=False)
    if rc != 0:
        tail = out.strip().splitlines()[-1] if out.strip() else "нет вывода"
        raise BackupError(
            f"не удалось получить список ВМ (qm list, код {rc}): {tail}")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].isdigit():
            # qm list: VMID NAME STATUS MEM(MB) BOOTDISK(GB) PID;
            # имя бывает пустым — тогда второй столбец сразу статус
            if parts[1] in KNOWN_STATUSES:
                name, status = "", parts[1]
            else:
                name, status = parts[1], parts[2]
            guests.append({"vmid": int(parts[0]), "gtype": "qemu",
                           "name": name, "status": status})

    rc, out = ssh_run(cfg, "pct list", check=False)
    if rc != 0:
        tail = out.strip().splitlines()[-1] if out.strip() else "нет вывода"
        raise BackupError(
            f"не удалось получить список контейнеров (pct list, код {rc}): {tail}. "
            "Выполнение остановлено: часть гостей могла бы остаться без бэкапа")
    for line in out.splitlines():
        parts = line.split()
        # pct list: VMID Status [Lock] Name. Имя собираем целиком
        # (" ".join), а не по последнему слову; столбец Lock опознаём
        # по известным значениям блокировок, а «-» означает, что
        # блокировки нет, и в имя контейнера не попадает
        if len(parts) >= 3 and parts[0].isdigit():
            rest = parts[2:]
            if rest and (rest[0] == "-" or rest[0] in KNOWN_LOCKS):
                rest = rest[1:]
            guests.append({"vmid": int(parts[0]), "gtype": "lxc",
                           "status": parts[1], "name": " ".join(rest)})
    return guests


def guest_label(gtype):
    return "VM" if gtype == "qemu" else "CT"


def pick_targets(guests, include, exclude):
    """include задан -> только эти гости; иначе все, кроме exclude."""
    by_id = {g["vmid"]: g for g in guests}
    if include:
        targets = []
        for vmid in include:
            if vmid in by_id:
                targets.append(by_id[vmid])
            else:
                LOG.warning("Гость %s из include-списка не найден на ноде — пропущен", vmid)
        return targets
    targets = [g for g in guests if g["vmid"] not in exclude]
    skipped = [g["vmid"] for g in guests if g["vmid"] in exclude]
    if skipped:
        LOG.info("Исключены гости: %s", ", ".join(map(str, skipped)))
    return targets
