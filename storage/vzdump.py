# -*- coding: utf-8 -*-
"""Обычные vzdump-архивы: бэкап гостя, имеющиеся копии, удаление исходного.

Перенесено из proxmox_backup.py v5 без изменений: запуск vzdump на ноде,
конвейер «SHA256 сервера -> scp -> SHA256 локально -> структура архива»
для свежего архива, поиск уже имеющихся копий (pvesm list), их вывод
и уведомления, удаление исходного архива с ноды после успешной проверки
согласно BACKUP['delete_after_download']. Локальный подбор свободного
имени (_free_destination_path, суффиксы __dupN) находится в common.py:
он нужен трём модулям (vzdump, download, pbs), а перенос в
transfer/download.py создал бы циклический импорт transfer.download ↔
storage.pbs (pbs.py использует его при сохранении tar-архива снапшота).
"""

import logging
import os
import re
import shlex
import time
from datetime import datetime

from common import BackupError, Result, _free_destination_path
from logger import _plural, human_size
from proxmox.ssh import scp_pull, ssh_run
from transfer.verify import local_sha256, remote_sha256, verify_archive_structure

LOG = logging.getLogger("pve-backup")

# Разбор вывода «pvesm list <storage> --content backup» (уже имеющиеся копии):
# строка содержимого начинается с volid вида «storage:backup/имя»
VOLID_RE = re.compile(r"^\S+:backup/\S+$")
VZDUMP_DATE_RE = re.compile(r"(\d{4}_\d{2}_\d{2}-\d{2}_\d{2}_\d{2})")
PBS_DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)")

VZDUMP_ARCHIVE_RE = re.compile(r"creating vzdump archive '(.+?)'")


def _volid_date(volid):
    """Дата из имени volid: vzdump «...-ГГГГ_ММ_ДД-ЧЧ_ММ_СС» или PBS (ISO-8601)."""
    match = VZDUMP_DATE_RE.search(volid)
    if match:
        try:
            return datetime.strptime(
                match.group(1), "%Y_%m_%d-%H_%M_%S").strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return match.group(1)
    match = PBS_DATE_RE.search(volid)
    return match.group(1) if match else ""


def list_storage_backups(cfg, storage):
    """Уже имеющиеся в хранилище резервные копии (pvesm list --content backup).

    Возвращает список {volid, size, date}, отсортированный по volid.
    Ошибки выполнения команды на ноде пробрасываются вызывающему коду.
    """
    rc, out = ssh_run(cfg,
                      f"pvesm list {shlex.quote(str(storage))} --content backup")
    entries = []
    for line in out.splitlines():
        tokens = line.split()
        if len(tokens) < 2 or not VOLID_RE.match(tokens[0]):
            continue                        # заголовок таблицы и прочий шум
        size = 0
        for token in tokens[1:5]:           # столбцы Format/Type/Size/... — ищем число
            if token.isdigit():
                size = int(token)
                break
        entries.append({"volid": tokens[0], "size": size,
                        "date": _volid_date(tokens[0])})
    entries.sort(key=lambda entry: entry["volid"])
    return entries


def print_backup_table(entries):
    """Печатает список копий: volid, размер, дата из имени архива."""
    print(f"  {'Резервная копия (volid)':<62} {'Размер':>10}  Дата")
    for entry in entries:
        volid = entry["volid"]
        if len(volid) > 62:
            volid = volid[:59] + "..."
        print(f"  {volid:<62} {human_size(entry['size']):>10}  "
              f"{entry['date'] or '-'}")


def _announce_existing(entries, storage):
    """Сообщает о копиях, уже лежащих в хранилище (лог; детали — в DEBUG)."""
    n = len(entries)
    total = sum(entry["size"] for entry in entries)
    LOG.info("Внимание: в хранилище «%s» уже есть %s, %s до этого запуска "
             "(суммарно %s)", storage,
             f"{n} {_plural(n, 'резервная копия', 'резервные копии', 'резервных копий')}",
             _plural(n, "созданная", "созданные", "созданных"),
             human_size(total))
    for entry in entries:
        LOG.debug("Существующий бэкап: %s (%s%s)", entry["volid"],
                  human_size(entry["size"]),
                  f", {entry['date']}" if entry["date"] else "")


def report_existing_backups(cfg, storage):
    """Неинтерактивное уведомление о копиях, уже лежащих в хранилище.

    Проверка информационная: если pvesm list не выполнился, бэкап не
    прерывается — в лог пишется предупреждение. Полный список попадает
    в лог (DEBUG). В живом терминале вместо этой функции работает
    interactive_existing_download: нумерованный список и выбор копий
    для скачивания.
    """
    try:
        entries = list_storage_backups(cfg, storage)
    except BackupError as exc:
        LOG.warning("Не удалось проверить хранилище «%s» на уже имеющиеся "
                    "резервные копии: %s", storage, exc)
        return
    if not entries:
        LOG.info("В хранилище «%s» ранее созданных резервных копий нет", storage)
        return
    _announce_existing(entries, storage)


def run_vzdump(cfg, guest):
    """Запускает vzdump. Возвращает (путь_к_архиву_на_ноде | None, вывод)."""
    backup = cfg["backup"]
    remote_cmd = (f"vzdump {guest['vmid']}"
                  f" --mode {backup['mode']}"
                  f" --compress {backup['compress']}"
                  f" --storage {shlex.quote(str(backup['storage']))}")
    LOG.info("[%s] Запуск vzdump (режим %s, хранилище %s)...",
             guest["vmid"], backup["mode"], backup["storage"])
    rc, out = ssh_run(cfg, remote_cmd, check=False, passthrough=True)
    match = VZDUMP_ARCHIVE_RE.search(out)
    if rc != 0 or not match:
        return None, out
    return match.group(1), out


def delete_remote_archive(cfg, archive_path):
    """Удаляет с ноды архив и служебные файлы (.notes, .log).

    Возвращает True, если rm на ноде прошёл успешно, и False при любой
    ошибке удаления. Молча терять архив нельзя: вызывающий код обязан
    сообщить пользователю, что архив остался на ноде.
    """
    directory, _, base = archive_path.rpartition("/")
    if not directory:
        directory = "."
    stem = re.sub(r"\.(vma|tar)(\.(zst|gz|lzo))?$", "", base)
    targets = [archive_path, f"{directory}/{base}.notes", f"{directory}/{stem}.log"]
    cmd = "rm -f -- " + " ".join(shlex.quote(t) for t in targets)
    rc, out = ssh_run(cfg, cmd, check=False)
    if rc != 0:
        LOG.warning("rm на ноде завершился с кодом %s: %s", rc,
                    out.strip()[-300:] or "нет вывода")
        return False
    return True


def backup_guest(cfg, guest, dest_dir):
    vmid = guest["vmid"]
    delete_enabled = bool(cfg["backup"].get("delete_after_download", True))
    started = time.monotonic()

    archive_path, vzdump_out = run_vzdump(cfg, guest)
    if archive_path is None:
        tail = "\n".join(vzdump_out.strip().splitlines()[-15:]) or "(вывод пуст)"
        return Result(vmid, guest["name"], guest["gtype"], False,
                      f"vzdump завершился с ошибкой:\n{tail}")

    archive_name = archive_path.rsplit("/", 1)[-1]
    LOG.info("[%s] Архив создан на ноде: %s", vmid, archive_path)

    local_tmp = dest_dir / f".tmp_{archive_name}"
    final_path = None
    reused = False          # локальная идентичная копия уже была — не качали
    warning = ""
    try:
        remote_sum = remote_sha256(cfg, archive_path)
        LOG.info("[%s] SHA256 на сервере: %s", vmid, remote_sum)

        # Существующие локальные файлы никогда не перезаписываются:
        # os.replace молча затирал бы копию с тем же именем.
        local_final = dest_dir / archive_name
        if local_final.exists():
            existing_sum = local_sha256(local_final)
            if existing_sum == remote_sum:
                LOG.info("[%s] Локальная копия %s уже существует и идентична "
                         "архиву — скачивание пропущено", vmid, archive_name)
                final_path = local_final
                reused = True
            else:
                LOG.warning("[%s] Файл %s уже есть локально и отличается от "
                            "нового архива — перезапись запрещена, новая копия "
                            "будет сохранена под другим именем",
                            vmid, archive_name)

        if final_path is None:
            try:
                LOG.info("[%s] Копирование по сети (scp)...", vmid)
                rc, out = scp_pull(cfg, archive_path, local_tmp)
                if rc != 0:
                    tail = out.strip().replace("\r", " ").splitlines()[-3:]
                    raise BackupError(
                        f"scp завершился с кодом {rc}: {' | '.join(tail)}")
                local_sum = local_sha256(local_tmp)
                LOG.info("[%s] SHA256 локально:   %s", vmid, local_sum)
                if local_sum != remote_sum:
                    raise BackupError(
                        "контрольные суммы не совпали — временный файл удалён, "
                        f"архив на сервере сохранён ({archive_path})")
                target = (local_final if not local_final.exists()
                          else _free_destination_path(dest_dir, archive_name))
                os.replace(local_tmp, target)
                final_path = target
            finally:
                local_tmp.unlink(missing_ok=True)

        ok, struct_detail = verify_archive_structure(final_path)
        if not ok:
            if reused:
                raise BackupError(
                    f"структура архива повреждена ({struct_detail}) — ранее "
                    f"созданная локальная копия оставлена как есть, архив на "
                    f"сервере сохранён ({archive_path})")
            final_path.unlink(missing_ok=True)
            raise BackupError(
                f"структура архива повреждена ({struct_detail}) — локальная "
                f"копия удалена, архив на сервере сохранён ({archive_path})")
        LOG.info("[%s] Структура архива: %s", vmid, struct_detail)

        if delete_enabled:
            if delete_remote_archive(cfg, archive_path):
                LOG.info("[%s] Целостность подтверждена, архив удалён с сервера",
                         vmid)
            else:
                warning = ("архив НЕ удалён с сервера (ошибка удаления) — "
                           "удалите его вручную")
                LOG.warning("[%s] %s: %s", vmid, warning, archive_path)
        else:
            LOG.info("[%s] Архив на сервере оставлен "
                     "(BACKUP['delete_after_download'] = False)", vmid)
    finally:
        local_tmp.unlink(missing_ok=True)

    size = final_path.stat().st_size
    duration = time.monotonic() - started
    detail = f"{final_path.name} ({human_size(size)}, {duration:.0f} c)"
    if reused:
        detail += "; идентичная копия уже была локально — скачивание пропущено"
    if warning:
        detail += f"; {warning}"
    return Result(vmid, guest["name"], guest["gtype"], True, detail,
                  archive=final_path.name, size=size, warning=warning)
