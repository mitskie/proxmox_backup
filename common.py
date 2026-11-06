# -*- coding: utf-8 -*-
"""Общие типы и вспомогательные функции проекта Proxmox Backup Script.

Небольшой общий модуль (допускается п. 4.2 ТЗ по реструктуризации):
исключения, результаты операций и те помощники, которые нужны сразу
нескольким модулям (config, proxmox, storage, transfer, main). Вынесены,
чтобы общие функции не дублировались и не возникало циклических импортов.

Весь код перенесён из proxmox_backup.py v5 без изменений.
"""

from dataclasses import dataclass


class BackupError(Exception):
    """Ошибочная ситуация при бэкапе или в конфигурации."""


class AuthError(BackupError):
    """Ошибка аутентификации SSH."""


class RemoteCommandError(BackupError):
    """Ошибка выполнения команды на ноде Proxmox по SSH."""


@dataclass
class Result:
    vmid: int
    name: str
    gtype: str
    ok: bool
    detail: str
    archive: str = ""
    size: int = 0
    warning: str = ""


@dataclass
class DownloadResult:
    """Итог скачивания одной уже существующей резервной копии."""
    volid: str
    ok: bool
    detail: str
    local_name: str = ""
    size: int = 0
    warning: str = ""


def _ask(prompt):
    try:
        return input(prompt)
    except EOFError:
        raise BackupError("STDIN закрыт — интерактивный ввод невозможен") from None


def _free_destination_path(dest_dir, archive_name):
    """Путь в dest_dir, не занятый существующим файлом (без перезаписи).

    При конфликте имён добавляет суффикс __dup1, __dup2, ... перед
    последним расширением: vzdump-...vma.zst -> vzdump-...vma__dup1.zst.
    """
    candidate = dest_dir / archive_name
    if not candidate.exists():
        return candidate
    suffix = candidate.suffix
    stem = archive_name[:-len(suffix)] if suffix else archive_name
    counter = 1
    while True:
        candidate = dest_dir / f"{stem}__dup{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1
