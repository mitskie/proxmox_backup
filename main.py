#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proxmox_backup.py — резервное копирование ВМ и LXC-контейнеров Proxmox
на локальную машину.

Запускается на рабочей машине (той, в каталог которой складываются копии)
и по SSH управляет нодой Proxmox VE:

  1. Получает список гостей: qm list (ВМ) + pct list (LXC-контейнеры).
  2. Проверяет, что уже лежит в выбранном хранилище ноды (pvesm list):
     сообщает о резервных копиях, созданных ранее; в живом терминале
     печатает их нумерованный список и предлагает выбрать копии для
     скачивания (--download-existing — только скачивание имеющихся копий,
     --list-backups — только список, без бэкапа).
  3. Формирует целевой список: из конфига (include/exclude) либо
     интерактивно (--interactive).
  4. Для каждого гостя запускает vzdump на ноде (режим и хранилище —
     из конфига или выбраны интерактивно).
  5. Считает SHA256 архива на сервере.
  6. Копирует архив по сети (scp) во временный файл .tmp_*, считает SHA256
     локально, сравнивает с серверной суммой, затем проверяет структуру
     архива (сигнатуры форматов vzdump: VMA/tar/gzip/zstd/lzop).
  7. Локальные копии НИКОГДА не удаляются и не перезаписываются: если файл
     с таким именем уже есть и идентичен новому архиву — скачивание
     пропускается; если отличается — новая копия сохраняется под именем
     *_dupN. Если BACKUP['delete_after_download'] = True (или не задан
     --keep-on-server) и все проверки пройдены — архив и служебные файлы
     (.log/.notes) удаляются с сервера; ошибка удаления не замалчивается.
     Если проверки НЕ пройдены — временный файл удаляется, архив на
     сервере СОХРАНЯЕТСЯ, гость помечается как ошибочный.
  8. Печатает итоговую сводку; код возврата 0 — успех, 1 — были ошибки,
     2 — ошибка конфигурации/подключения, 130 — прервано пользователем.
  9. Хранилища Proxmox Backup Server (тип pbs в pvesm status) обслуживаются
     отдельно: список снапшотов, нумерованный выбор и скачивание через
     proxmox-backup-client на ноде (scp к PBS неприменим). Снапшоты PBS
     никогда не удаляются — их жизненный цикл управляется prune/GC на PBS.
     Пароль PBS не попадает в командные строки и логи: он читается прямо
     на ноде во временный файл (права 600, удаляется после операции) и
     передаётся клиенту через PBS_PASSWORD_FILE; для зашифрованных
     хранилищ ключ проверяется (обычный файл, читается, не пуст) и
     передаётся клиенту параметром --keyfile. Очистка временных файлов
     ноды выполняется при любом исходе и подтверждается проверкой их
     отсутствия; если нода недоступна, в лог пишется предупреждение,
     что временные файлы могли остаться на узле.

Только стандартная библиотека Python 3.8+ (никаких pip-пакетов).
Подключение: по SSH-ключу (BatchMode) или по паролю (ввод через
псевдо-терминал; пароль берётся из конфига или запрашивается флагом
--ask-pass).
Конфигурация — Python-файл backup_config.py (см. пример рядом).

Точка входа программы. Реализация разбита на модули: config.py (конфиг),
logger.py (логирование), common.py (общие типы), proxmox/ (ssh, api,
гости), storage/ (хранилища, vzdump, PBS), transfer/ (скачивание,
проверки). Привычный запуск `python3 proxmox_backup.py` сохранён:
файл proxmox_backup.py делегирует выполнение в main() этого модуля.
"""

import argparse
import getpass
import logging
import sys
from pathlib import Path

from common import BackupError, RemoteCommandError, Result, _ask
from config import MODES, find_config, load_config, parse_vm_ids
from logger import _level, _plural, human_size, setup_logging
from proxmox.api import check_prerequisites, test_connection
from proxmox.guests import get_node_guests, guest_label, pick_targets
from storage.discovery import get_storages, get_storage_type
from storage.vzdump import (backup_guest, list_storage_backups,
                            print_backup_table, report_existing_backups)
from transfer.download import cleanup_stale_tmp, interactive_existing_download

LOG = logging.getLogger("pve-backup")


def list_backups_mode(cfg):
    """Режим --list-backups: показать копии хранилища и завершиться (без бэкапа)."""
    try:
        test_connection(cfg)
        LOG.info("SSH-соединение с нодой установлено")
    except BackupError as exc:
        LOG.error("%s", exc)
        return 2
    storage = str(cfg["backup"]["storage"])
    try:
        storages = get_storages(cfg)
    except BackupError as exc:
        LOG.error("%s", exc)
        return 2
    if storage not in {s["name"] for s in storages}:
        LOG.error("Хранилище «%s» не найдено на ноде или не разрешено для "
                  "backup. Доступные: %s", storage,
                  ", ".join(s["name"] for s in storages) or "нет")
        return 2
    try:
        entries = list_storage_backups(cfg, storage)
    except BackupError as exc:
        LOG.error("%s", exc)
        return 2
    if not entries:
        LOG.info("В хранилище «%s» резервных копий не найдено", storage)
        return 0
    n = len(entries)
    total = sum(entry["size"] for entry in entries)
    print()
    print(f"В хранилище «{storage}» — {n} "
          f"{_plural(n, 'резервная копия', 'резервные копии', 'резервных копий')} "
          f"({human_size(total)}):")
    print_backup_table(entries)
    print()
    if get_storage_type(storages, storage) == "pbs":
        print("Хранилище типа PBS (Proxmox Backup Server): выбранные снапшоты "
              "можно скачать командой --download-existing.")
    return 0


def download_existing_mode(cfg, dest_dir):
    """Режим --download-existing: только скачивание имеющихся копий, без бэкапа."""
    try:
        test_connection(cfg)
        LOG.info("SSH-соединение с нодой установлено")
        storages = get_storages(cfg)
    except BackupError as exc:
        LOG.error("%s", exc)
        return 2
    storage = str(cfg["backup"]["storage"])
    if storage not in {s["name"] for s in storages}:
        LOG.error("Хранилище «%s» не найдено на ноде или не разрешено для "
                  "backup. Доступные: %s", storage,
                  ", ".join(s["name"] for s in storages) or "нет")
        return 2
    try:
        failures = interactive_existing_download(cfg, storage, storages, dest_dir)
    except BackupError as exc:
        LOG.error("%s", exc)
        return 2
    return 1 if failures else 0


# ----------------------------------------------------------------------------
# Работа с гостями ноды
# ----------------------------------------------------------------------------

def _ask_ids(prompt, valid_ids):
    while True:
        raw = _ask(prompt).strip()
        try:
            ids = parse_vm_ids([raw]) if raw else []
        except ValueError:
            print("  ? ID должны быть целыми числами через запятую")
            continue
        if not ids:
            print("  ? перечислите хотя бы один ID")
            continue
        unknown = [i for i in ids if i not in valid_ids]
        if unknown:
            print(f"  ? на ноде нет гостей с ID: {', '.join(map(str, unknown))}")
            continue
        return ids


def interactive_select(guests, storages, cfg, args):
    """Интерактивный выбор: гости, хранилище, режим. -> (include, exclude, storage, mode)"""
    print()
    print("Найдены гости на ноде:")
    print(f"  {'ID':<7}{'Тип':<5}{'Статус':<11}Имя")
    for g in guests:
        print(f"  {g['vmid']:<7}{guest_label(g['gtype']):<5}{g['status']:<11}{g['name']}")

    include = exclude = None
    if args.include is None and args.exclude is None:
        print()
        print("Каких гостей бэкапить?")
        print("  1) все перечисленные")
        print("  2) только выбранные (перечислить ID)")
        print("  3) все, кроме исключений (перечислить ID)")
        print("  4) применить списки include/exclude из конфига")
        by_id = {g["vmid"] for g in guests}
        while True:
            raw = _ask(f"Вариант [1/2/3/4, Enter = 4 (конфиг)]: ").strip()
            if raw == "" or raw == "4":
                include, exclude = cfg["vms"]["include"], cfg["vms"]["exclude"]
                break
            if raw == "1":
                include, exclude = [], []
                break
            if raw == "2":
                include, exclude = _ask_ids("ID через запятую: ", by_id), []
                break
            if raw == "3":
                include, exclude = [], _ask_ids("ID через запятую: ", by_id)
                break
            print("  ? введите 1, 2, 3 или 4")
    else:
        include = cfg["vms"]["include"] if args.include is not None else None
        exclude = cfg["vms"]["exclude"] if args.exclude is not None else None
        if include is not None:
            exclude = []
        LOG.info("Список гостей задан ключами командной строки")

    storage = cfg["backup"]["storage"]
    if args.storage is None:
        print()
        print("Хранилища ноды для транзитных архивов:")
        for s in storages:
            avail = s.get("avail")
            if avail is None:                  # неизвестно — не путать с 0
                size = ", свободное место: неизвестно"
            else:
                size = f", свободно {human_size(avail)}" if avail else ""
            print(f"  {s['name']:<16}{s['type']:<8}{s['status']}{size}")
        names = {s["name"] for s in storages}
        while True:
            raw = _ask(f"Хранилище [Enter = {storage}]: ").strip()
            if raw == "":
                break
            if raw in names:
                if get_storage_type(storages, raw) == "pbs":
                    print(f"  ? «{raw}» — хранилище Proxmox Backup Server: "
                          "vzdump в PBS этим скриптом не поддерживается, "
                          "нужно файловое хранилище (dir/nfs/cifs/...)")
                    continue
                storage = raw
                break
            print("  ? такого хранилища нет в списке")

    mode = cfg["backup"]["mode"]
    if args.mode is None:
        print()
        print("Режимы бэкапа vzdump:")
        print("  snapshot — гость продолжает работать (снапшот дисков)")
        print("  suspend  — гость ставится на паузу на время бэкапа")
        print("  stop     — гость останавливается и запускается снова после бэкапа")
        while True:
            raw = _ask(f"Режим [Enter = {mode}]: ").strip()
            if raw == "":
                break
            if raw in MODES:
                mode = raw
                break
            print("  ? введите snapshot, suspend или stop")

    return include or [], exclude or [], storage, mode


def confirm_start():
    raw = _ask("Начать бэкап? [Y/n]: ").strip().lower()
    return raw not in ("n", "no", "н", "нет")


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

EXAMPLES = """примеры:
  proxmox_backup.py                                  # по конфигу, неинтерактивно
  proxmox_backup.py -i                               # интерактивный выбор всего
  proxmox_backup.py --include 100 101 --mode stop    # только эти ВМ, с остановкой
  proxmox_backup.py --exclude 102,105                # все, кроме исключённых
  proxmox_backup.py --ask-pass                       # пароль SSH спросит в терминале
  proxmox_backup.py --dest /mnt/nas/pve-backups      # другой каталог назначения
  proxmox_backup.py --list-backups                   # что уже лежит в хранилище ноды
  proxmox_backup.py --download-existing              # скачать выбранные имеющиеся копии
"""


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="proxmox_backup.py",
        description="Резервное копирование ВМ и LXC Proxmox по SSH: vzdump -> scp -> "
                    "проверка SHA256 -> удаление архива на сервере. "
                    "Только стандартная библиотека Python.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLES,
    )
    parser.add_argument("-c", "--config", metavar="FILE",
                        help="путь к Python-конфигу (по умолчанию ./backup_config.py, "
                             "затем — рядом со скриптом)")
    parser.add_argument("-i", "--interactive", action="store_true",
                        help="интерактивный выбор гостей, хранилища и режима")
    parser.add_argument("--include", nargs="+", metavar="VMID",
                        help="бэкапить только этих гостей: --include 100,101 или "
                             "--include 100 101 (перекрывает конфиг)")
    parser.add_argument("--exclude", nargs="+", metavar="VMID",
                        help="исключить гостей: --exclude 100,101 (перекрывает конфиг)")
    parser.add_argument("--mode", choices=MODES,
                        help="режим vzdump: snapshot / suspend / stop (перекрывает конфиг)")
    parser.add_argument("--storage", metavar="NAME",
                        help="хранилище Proxmox для транзитных архивов (перекрывает конфиг)")
    parser.add_argument("-d", "--dest", metavar="DIR",
                        help="локальный каталог для копий (перекрывает конфиг)")
    parser.add_argument("--ask-pass", action="store_true",
                        help="запросить SSH-пароль в терминале перед началом работы")
    parser.add_argument("--keep-on-server", action="store_true",
                        help="не удалять архив на сервере после успешной проверки "
                             "(перекрывает BACKUP['delete_after_download'])")
    parser.add_argument("--list-backups", action="store_true",
                        help="показать, какие резервные копии уже лежат в "
                             "хранилище ноды (pvesm list), и завершиться без бэкапа")
    parser.add_argument("--download-existing", action="store_true",
                        help="скачать уже имеющиеся копии из хранилища ноды: "
                             "нумерованный список и выбор номерами через запятую; "
                             "завершиться без бэкапа гостей")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING"),
                        default="INFO", help="детальность логов в консоли (по умолчанию INFO)")
    return parser.parse_args(argv)


def resolve_password(cfg, args):
    """Пароль: --ask-pass > конфиг. None -> аутентификация по ключу."""
    if args.ask_pass:
        proxmox = cfg["proxmox"]
        try:
            password = getpass.getpass(
                f"SSH-пароль для {proxmox['user']}@{proxmox['host']}: ")
        except (EOFError, OSError):
            raise BackupError("--ask-pass требует интерактивного терминала") from None
        if not password:
            raise BackupError("пустой пароль — отменено")
        return password
    return cfg["proxmox"]["password"] or None


def main(argv=None):
    args = parse_args(argv)

    try:
        cfg_path = find_config(args.config)
        cfg = load_config(cfg_path)
        if args.include is not None:
            cfg["vms"]["include"] = parse_vm_ids(args.include)
        if args.exclude is not None:
            cfg["vms"]["exclude"] = parse_vm_ids(args.exclude)
        password = resolve_password(cfg, args)
        cfg["proxmox"]["_password"] = password
    except (BackupError, ValueError) as exc:
        sys.stderr.write(f"Ошибка конфигурации/аргументов: {exc}\n")
        return 2

    if args.mode:
        cfg["backup"]["mode"] = args.mode
    if args.storage:
        cfg["backup"]["storage"] = args.storage
    if args.dest:
        cfg["backup"]["destination"] = args.dest
    if args.keep_on_server:
        cfg["backup"]["delete_after_download"] = False

    logfile = setup_logging(cfg, _level(args.log_level, logging.INFO))
    LOG.info("Аутентификация SSH: %s",
             "по паролю" if cfg["proxmox"]["_password"] else "по ключу (BatchMode)")

    backup = cfg["backup"]
    proxmox = cfg["proxmox"]
    LOG.info("=== Proxmox Backup Puller ===")
    LOG.info("Конфиг: %s", cfg_path)
    LOG.info("Нода: %s@%s:%s | хранилище: %s | режим: %s | компрессия: %s",
             proxmox["user"], proxmox["host"], proxmox["port"],
             backup["storage"], backup["mode"], backup["compress"])
    LOG.info("Удаление архива на сервере после проверки: %s",
             "да" if backup["delete_after_download"]
             else "нет — архивы остаются на ноде")

    if args.list_backups:
        return list_backups_mode(cfg)

    dest_dir = Path(backup["destination"]).expanduser()
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        LOG.error("Не удалось создать каталог назначения %s: %s", dest_dir, exc)
        return 2
    LOG.info("Каталог назначения: %s (старые копии не удаляются)", dest_dir.resolve())
    cleanup_stale_tmp(dest_dir)

    if args.download_existing:
        return download_existing_mode(cfg, dest_dir)

    try:
        test_connection(cfg)
        LOG.info("SSH-соединение с нодой установлено")
        check_prerequisites(cfg)
        storages = get_storages(cfg)
        guests = get_node_guests(cfg)
    except (BackupError, RemoteCommandError) as exc:
        LOG.error("%s", exc)
        return 2

    if not guests:
        LOG.error("На ноде не найдено ни одной ВМ или контейнера.")
        return 2
    LOG.info("На ноде гостей: %s",
             ", ".join(f"{g['vmid']}({g['name']},{guest_label(g['gtype'])})"
                       for g in guests))

    if args.interactive:
        try:
            include, exclude, storage, mode = interactive_select(guests, storages, cfg, args)
        except BackupError as exc:
            LOG.error("%s", exc)
            return 2
        cfg["vms"]["include"], cfg["vms"]["exclude"] = include, exclude
        cfg["backup"]["storage"], cfg["backup"]["mode"] = storage, mode
        LOG.info("Выбрано: хранилище %s, режим %s", storage, mode)

    if cfg["backup"]["storage"] not in {s["name"] for s in storages}:
        LOG.error("Хранилище «%s» не найдено на ноде или не разрешено для backup. "
                  "Доступные: %s", cfg["backup"]["storage"],
                  ", ".join(s["name"] for s in storages) or "нет")
        return 2
    if get_storage_type(storages, cfg["backup"]["storage"]) == "pbs":
        LOG.error("Хранилище «%s» — Proxmox Backup Server (тип pbs): создание "
                  "транзитных vzdump-архивов в PBS этим скриптом не поддерживается. "
                  "Укажите файловое хранилище (dir/nfs/cifs/...); для просмотра и "
                  "скачивания уже имеющихся PBS-снапшотов есть --list-backups и "
                  "--download-existing.", cfg["backup"]["storage"])
        return 2

    # Копии, уже лежащие в хранилище: сообщаем о них ДО создания новых архивов;
    # в живом терминале сразу предлагаем выбрать и скачать нужные
    download_failures = 0
    if args.interactive or sys.stdin.isatty():
        try:
            download_failures = interactive_existing_download(
                cfg, cfg["backup"]["storage"], storages, dest_dir)
        except BackupError as exc:
            LOG.warning("Не удалось проверить хранилище «%s» на уже имеющиеся "
                        "резервные копии: %s", cfg["backup"]["storage"], exc)
    else:
        report_existing_backups(cfg, cfg["backup"]["storage"])

    targets = pick_targets(guests, cfg["vms"]["include"], cfg["vms"]["exclude"])
    if not targets:
        LOG.error("Список гостей для бэкапа пуст — проверьте include/exclude.")
        return 1
    LOG.info("К бэкапу: %s (режим %s)",
             ", ".join(f"{g['vmid']}({guest_label(g['gtype'])})" for g in targets),
             cfg["backup"]["mode"])

    if args.interactive:
        try:
            if not confirm_start():
                LOG.info("Отменено пользователем.")
                return 0
        except BackupError as exc:
            LOG.error("%s", exc)
            return 2

    results = []
    for guest in targets:
        LOG.info("--- Гость %s (%s, %s, статус: %s) ---",
                 guest["vmid"], guest["name"], guest_label(guest["gtype"]),
                 guest["status"])
        try:
            results.append(backup_guest(cfg, guest, dest_dir))
        except KeyboardInterrupt:
            LOG.warning("Прервано пользователем: гость %s не завершён "
                        "(частичный архив мог остаться на ноде).", guest["vmid"])
            raise
        except (BackupError, RemoteCommandError) as exc:
            results.append(Result(guest["vmid"], guest["name"], guest["gtype"],
                                  False, str(exc)))
        except Exception as exc:   # непредвиденные ошибки не останавливают остальные
            results.append(Result(guest["vmid"], guest["name"], guest["gtype"],
                                  False, f"непредвиденная ошибка: {exc}"))

    LOG.info("=== Итог ===")
    ok_count = 0
    for result in results:
        if result.ok:
            ok_count += 1
        mark = "OK  " if result.ok else "FAIL"
        LOG.info("%s %s (%s, %s): %s", mark, result.vmid, result.name,
                 guest_label(result.gtype), result.detail.replace("\n", " | "))
    failed = len(results) - ok_count
    LOG.info("Успешно: %d/%d, с ошибками: %d.", ok_count, len(results), failed)
    not_deleted = [r for r in results if r.ok and r.warning]
    if not_deleted:
        LOG.warning("Внимание: копии получены, но архивы НЕ удалены на сервере: %s",
                    ", ".join(str(r.vmid) for r in not_deleted))
    if failed:
        LOG.warning("Архивы неуспешных гостей НЕ удалены с сервера — проверьте ноду вручную.")
    LOG.info("Лог: %s", logfile)
    return 0 if failed == 0 and download_failures == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("Прервано пользователем.\n")
        sys.exit(130)
