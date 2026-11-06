# -*- coding: utf-8 -*-
"""Хранилища ноды: список, типы, доступность, свободное место.

Перенесено из proxmox_backup.py v5 без изменений: разбор вывода
`pvesm status -content backup` по строке заголовка (Name Type Status
Total Used Available %), правила «неизвестного» свободного места
(отсутствующий или нечитаемый Available — не ноль) и резервный разбор
со стандартным порядком столбцов сохранены.
"""

import logging

from proxmox.ssh import ssh_run

LOG = logging.getLogger("pve-backup")


def _status_int(parts, index):
    """Целое из столбца pvesm status; '' / '33.33%' / мусор -> None."""
    if index is None or index >= len(parts):
        return None
    try:
        return int(parts[index].rstrip("%"))
    except ValueError:
        return None


def get_storages(cfg):
    """Хранилища ноды, разрешённые для содержимого типа backup.

    Столбцы разбираются по строке заголовка pvesm status
    (Name Type Status Total Used Available %), а не по жёстким индексам:
    Available — это свободное место, и его нельзя путать с процентом
    использования в последнем столбце. Если заголовок найден, но столбца
    Available в нём нет (или значение не удалось разобрать) — свободное
    место помечается как неизвестное (None), а НЕ нулём: отсутствие
    данных не должно выглядеть как «хранилище заполнено». Если заголовок
    не найден вовсе — резервный разбор стандартного порядка столбцов
    (с предупреждением). Неразборчивые строки не роняют скрипт —
    предупреждение и пропуск строки.
    """
    rc, out = ssh_run(cfg, "pvesm status -content backup")
    lines = [line for line in out.splitlines() if line.strip()]
    header_idx, columns = None, {}
    for i, line in enumerate(lines):
        tokens = line.split()
        if tokens and tokens[0] == "Name" and len(tokens) >= 3:
            header_idx = i
            columns = {token: pos for pos, token in enumerate(tokens)}
            break
    if header_idx is None:
        # Нестандартный вывод без заголовка — стандартный порядок столбцов
        # pvesm status: Name Type Status Total Used Available %
        LOG.warning("pvesm status: не найдена строка заголовка — использую "
                    "резервный разбор со стандартным порядком столбцов")
        columns = {"Name": 0, "Type": 1, "Status": 2,
                   "Total": 3, "Available": 5}
        header_idx = -1
    missing = [name for name in ("Name", "Type", "Status")
               if name not in columns]
    if missing:
        LOG.warning("pvesm status: в заголовке нет столбцов: %s — часть "
                    "данных о хранилищах будет неполной", ", ".join(missing))
    if "Available" not in columns:
        LOG.warning("pvesm status: в заголовке нет столбца Available — "
                    "свободное место хранилищ будет показано как неизвестное")
    storages = []
    for line in lines[header_idx + 1:]:
        parts = line.split()
        if not parts or parts[0] == "Name":
            continue
        try:
            entry = {"name": parts[columns["Name"]],
                     "type": parts[columns["Type"]],
                     "status": parts[columns["Status"]]}
        except (KeyError, IndexError):
            LOG.warning("pvesm status: пропущена неразборчивая строка: %r",
                        line.strip()[:100])
            continue
        total = _status_int(parts, columns.get("Total"))
        entry["total"] = total if total is not None else 0
        if "Available" in columns:
            avail = _status_int(parts, columns["Available"])
            if avail is None:
                # Значение есть, но не разбирается: это НЕ достоверный ноль
                LOG.warning("pvesm status: не удалось разобрать свободное "
                            "место (Available) для хранилища «%s» — помечено "
                            "как неизвестное", entry["name"])
        else:
            avail = None                       # столбца нет: место неизвестно
        entry["avail"] = avail
        storages.append(entry)
    return storages


def get_storage_type(storages, name):
    """Тип хранилища (dir/nfs/pbs/...) по данным pvesm status; '' если не найдено."""
    for storage in storages:
        if storage["name"] == name:
            return storage["type"]
    return ""
