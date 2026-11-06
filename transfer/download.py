# -*- coding: utf-8 -*-
"""Скачивание и передача резервных копий на локальную машину.

Перенесено из proxmox_backup.py v5 без изменений: определение пути архива
на ноде (pvesm path), скачивание уже имеющихся копий файловых хранилищ
(scp + тот же конвейер проверок), диспетчер скачивания (файловое хранилище
или PBS), нумерованный список и интерактивный выбор копий, итоговая сводка
и работа с временными файлами передачи (cleanup_stale_tmp).

Локальный подбор свободного имени (_free_destination_path) находится
в common.py — он нужен трём модулям (vzdump, download, pbs), и перенос
его сюда создал бы циклический импорт transfer.download ↔ storage.pbs.
"""

import logging
import os
import shlex
import time

from common import (BackupError, DownloadResult, RemoteCommandError, _ask,
                    _free_destination_path)
from logger import human_size
from proxmox.ssh import scp_pull, ssh_run
from storage.discovery import get_storage_type
from storage.pbs import pbs_download_snapshot
from storage.vzdump import (_announce_existing, delete_remote_archive,
                            list_storage_backups)
from transfer.verify import local_sha256, remote_sha256, verify_archive_structure

LOG = logging.getLogger("pve-backup")


def resolve_volid_path(cfg, volid):
    """Путь файла на ноде для volid файлового хранилища (pvesm path)."""
    rc, out = ssh_run(cfg, f"pvesm path {shlex.quote(volid)}", check=False)
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    path = lines[-1] if lines else ""
    if rc != 0 or not path.startswith("/"):
        raise BackupError(
            f"не удалось определить путь архива {volid} на ноде "
            f"(pvesm path, код {rc}): {out.strip()[-200:] or 'нет вывода'}")
    return path


def download_file_archive(cfg, entry, dest_dir):
    """Скачивает уже существующий архив файлового хранилища через scp.

    Тот же конвейер проверок, что и для свежесозданных архивов: SHA256
    сервера и локально, структура архива, запрет перезаписи локальных
    файлов. При любой ошибке локальный временный файл удаляется, архив
    на сервере сохраняется.
    """
    volid = entry["volid"]
    delete_enabled = bool(cfg["backup"].get("delete_after_download", True))
    archive_name = volid.rsplit("/", 1)[-1]
    node_path = resolve_volid_path(cfg, volid)
    remote_sum = remote_sha256(cfg, node_path)
    LOG.info("SHA256 на сервере: %s", remote_sum)

    reused = False
    target = dest_dir / archive_name
    if target.exists():
        if local_sha256(target) == remote_sum:
            LOG.info("Локальная копия %s идентична архиву — скачивание "
                     "пропущено", archive_name)
            reused = True
        else:
            target = _free_destination_path(dest_dir, archive_name)
            LOG.warning("Файл %s уже есть локально и отличается от архива — "
                        "перезапись запрещена, копия сохраняется как %s",
                        archive_name, target.name)

    if not reused:
        local_tmp = dest_dir / f".tmp_{archive_name}"
        try:
            LOG.info("Копирование по сети (scp)...")
            rc, out = scp_pull(cfg, node_path, local_tmp)
            if rc != 0:
                tail = out.strip().replace("\r", " ").splitlines()[-3:]
                raise BackupError(f"scp завершился с кодом {rc}: {' | '.join(tail)}")
            if local_sha256(local_tmp) != remote_sum:
                raise BackupError(
                    "контрольные суммы не совпали — временный файл удалён, "
                    f"архив на сервере сохранён ({node_path})")
            os.replace(local_tmp, target)
        finally:
            local_tmp.unlink(missing_ok=True)

    ok, struct_detail = verify_archive_structure(target)
    if not ok:
        if not reused:
            target.unlink(missing_ok=True)
        raise BackupError(
            f"структура архива повреждена ({struct_detail}) — "
            + ("ранее созданная локальная копия оставлена как есть" if reused
               else "локальная копия удалена")
            + f", архив на сервере сохранён ({node_path})")
    LOG.info("Структура архива: %s", struct_detail)

    warning = ""
    if delete_enabled:
        if delete_remote_archive(cfg, node_path):
            LOG.info("Целостность подтверждена, архив удалён с сервера")
        else:
            warning = ("архив НЕ удалён с сервера (ошибка удаления) — "
                       "удалите его вручную")
            LOG.warning("%s: %s", warning, node_path)
    else:
        LOG.info("Архив на сервере оставлен "
                 "(BACKUP['delete_after_download'] = False)")

    size = target.stat().st_size
    detail = f"{target.name} ({human_size(size)})"
    if reused:
        detail += "; идентичная копия уже была локально — скачивание пропущено"
    return DownloadResult(volid, True, detail, local_name=target.name,
                          size=size, warning=warning)


def download_existing_entry(cfg, storage, storage_type, entry, dest_dir):
    """Скачивает одну выбранную копию; ошибки превращаются в FAIL-результат."""
    volid = entry["volid"]
    try:
        if storage_type == "pbs":
            return pbs_download_snapshot(cfg, entry, dest_dir, storage)
        return download_file_archive(cfg, entry, dest_dir)
    except (BackupError, RemoteCommandError) as exc:
        return DownloadResult(volid, False, str(exc))
    except Exception as exc:                    # непредвиденные ошибки — не стоп
        return DownloadResult(volid, False, f"непредвиденная ошибка: {exc}")


def print_numbered_backups(entries):
    """Нумерованный список найденных копий для интерактивного выбора."""
    print()
    print("Найденные резервные копии:")
    print()
    for number, entry in enumerate(entries, 1):
        extra = []
        if entry["size"]:
            extra.append(human_size(entry["size"]))
        if entry["date"]:
            extra.append(entry["date"])
        suffix = f" ({', '.join(extra)})" if extra else ""
        print(f"[{number}] {entry['volid']}{suffix}")
    print()


def ask_download_selection(total, require_input=False):
    """Интерактивный выбор копий номерами через запятую (по аналогии с VMID).

    Возвращает список выбранных номеров (1..total, без повторов, в порядке
    ввода) или пустой список при отказе (Enter). При require_input=True
    (режим --download-existing) закрытый STDIN считается ошибкой.
    """
    while True:
        try:
            print("Выберите резервные копии для скачивания")
            print("(номера через запятую, например 1,3,4; Enter — пропустить):")
            raw = _ask("> ").strip()
        except BackupError:
            if require_input:
                raise BackupError(
                    "STDIN закрыт — интерактивный выбор копий невозможен") from None
            print("Скачивание имеющихся копий пропущено")
            return []
        if not raw:
            print("Скачивание имеющихся копий пропущено")
            return []
        bad, numbers = [], []
        for token in (part.strip() for part in raw.split(",")):
            if not token:
                continue
            if token.isdigit() and 1 <= int(token) <= total:
                numbers.append(int(token))
            else:
                bad.append(token)
        if bad:
            print(f"  ? некорректный ввод: {', '.join(bad)} — введите номера "
                  f"от 1 до {total} через запятую (Enter — пропустить)")
            continue
        seen, unique = set(), []
        for number in numbers:
            if number in seen:
                print(f"  ? номер {number} указан повторно — учитываю один раз")
                continue
            seen.add(number)
            unique.append(number)
        return unique


def run_download_selection(cfg, storage, storages, entries, dest_dir):
    """Показывает нумерованный список, спрашивает выбор, скачивает выбранное."""
    print_numbered_backups(entries)
    chosen = ask_download_selection(len(entries))
    if not chosen:
        return []
    storage_type = get_storage_type(storages, storage)
    results = []
    for number in chosen:
        entry = entries[number - 1]
        LOG.info("--- Копия [%d] %s ---", number, entry["volid"])
        results.append(download_existing_entry(cfg, storage, storage_type,
                                               entry, dest_dir))
    print_download_summary(results)
    return results


def interactive_existing_download(cfg, storage, storages, dest_dir):
    """Живой диалог о копиях, уже лежащих в хранилище.

    Сообщает о наличии копий, печатает нумерованный список, предлагает
    выбрать (номера через запятую) и скачивает выбранные. Возвращает
    число неудачных скачиваний (0 — всё хорошо или нечего было качать).
    Ошибки pvesm list пробрасываются вызывающему коду.
    """
    entries = list_storage_backups(cfg, storage)
    if not entries:
        LOG.info("В хранилище «%s» ранее созданных резервных копий нет", storage)
        return 0
    _announce_existing(entries, storage)
    results = run_download_selection(cfg, storage, storages, entries, dest_dir)
    return sum(1 for result in results if not result.ok)


def print_download_summary(results):
    """Итог скачивания выбранных копий (в консоль и лог)."""
    LOG.info("=== Скачивание имеющихся копий: итог ===")
    ok_count = 0
    for result in results:
        if result.ok:
            ok_count += 1
        mark = "OK  " if result.ok else "FAIL"
        LOG.info("%s %s: %s", mark, result.volid,
                 result.detail.replace("\n", " | "))
        if result.ok and result.warning:
            LOG.warning("%s: %s", result.volid, result.warning)
    failed = len(results) - ok_count
    LOG.info("Скачано: %d, с ошибками: %d.", ok_count, failed)
    if failed:
        LOG.warning("Неудачные копии остались на сервере — проверьте ноду "
                    "вручную.")


def cleanup_stale_tmp(dest_dir, max_age_hours=24):
    """Удаляет недокачанные .tmp_* файлы старше суток (бэкапы не трогает)."""
    threshold = time.time() - max_age_hours * 3600
    for path in dest_dir.glob(".tmp_*"):
        try:
            if path.is_file() and path.stat().st_mtime < threshold:
                path.unlink()
                LOG.info("Удалён недокачанный временный файл %s", path.name)
        except OSError:
            pass
