# -*- coding: utf-8 -*-
"""Proxmox Backup Server: снапшоты, скачивание через proxmox-backup-client.

Перенесено из proxmox_backup.py v5 без изменений: обнаружение PBS-хранилищ,
чтение параметров из /etc/pve/storage.cfg, проверка наличия
proxmox-backup-client, подготовка временного файла пароля (права 600,
PBS_PASSWORD_FILE — пароль ни разу не попадает в командные строки и логи),
проверка ключа шифрования (эквивалент test -f/-r/-s, отказ ДО скачивания,
--keyfile во всех вызовах клиента), восстановление снапшота во временный
каталог, упаковка в tar и очистка временных ресурсов при любом исходе
(без подмены первоначального исключения, с подтверждением удаления).

Снапшоты PBS никогда не удаляются — их жизненным циклом управляют
prune/GC на сервере PBS.
"""

import json
import logging
import os
import re
import shlex
import time

from common import (BackupError, DownloadResult, RemoteCommandError,
                    _free_destination_path)
from logger import human_size
from proxmox.ssh import scp_pull, ssh_run
from transfer.verify import local_sha256, remote_sha256, verify_archive_structure

LOG = logging.getLogger("pve-backup")

PBS_CLIENT_HINT = (
    "на ноде не найдена утилита proxmox-backup-client — она необходима для "
    "скачивания копий из хранилища Proxmox Backup Server (снапшоты PBS — "
    "не обычные файлы .vma.zst, через scp их получить нельзя). Установите "
    "её на НОДЕ Proxmox и повторите:\n"
    "    apt update && apt install proxmox-backup-client")


def pbs_check_client(cfg):
    """Проверяет наличие proxmox-backup-client на ноде (для хранилищ PBS)."""
    rc, _ = ssh_run(cfg, "command -v proxmox-backup-client", check=False)
    if rc != 0:
        raise BackupError(PBS_CLIENT_HINT)


def _pbs_snapshot_from_volid(volid):
    """volid 'pbs1:backup/vm/105/2025-...' -> снапшот 'vm/105/2025-...'."""
    match = re.match(r"^[^:]+:backup/(.+)$", volid)
    if not match:
        raise BackupError(f"не удалось разобрать volid PBS-снапшота: {volid}")
    return match.group(1)


def _pbs_local_name(volid):
    """Локальное имя tar-архива снапшота: pbs-vm-105-2025-12-31T22-00-00Z.tar."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", _pbs_snapshot_from_volid(volid))
    return f"pbs-{safe}.tar"


def read_pbs_storage_config(cfg, storage):
    """Параметры PBS-хранилища из /etc/pve/storage.cfg на ноде."""
    rc, out = ssh_run(cfg, "cat /etc/pve/storage.cfg")
    params, in_block = {}, False
    for line in out.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():               # заголовок секции «тип: имя»
            head = line.split(":", 1)
            in_block = (len(head) == 2 and head[0].strip() == "pbs"
                        and head[1].strip() == storage)
            continue
        if in_block:
            key, _, value = line.strip().partition(" ")
            params[key.strip()] = value.strip()
    if "server" not in params or "datastore" not in params:
        raise BackupError(
            "в /etc/pve/storage.cfg на ноде нет корректного блока pbs для "
            f"хранилища «{storage}» (нужны параметры server и datastore)")
    # Значение password локально не нужно: временный файл с паролем
    # создаётся на ноде из тех же источников (см. _pbs_prepare_password_file).
    # Не держим секрет в словаре параметров, чтобы он случайно не попал
    # в сообщения об ошибках или логи.
    params.pop("password", None)
    return params


def _pbs_password_prepare_cmd(storage):
    """Команда создания на ноде временного файла с паролем PBS.

    Пароль читается СТРОГО на ноде из тех же источников, что и раньше
    (строка password в блоке хранилища в storage.cfg либо файл
    /etc/pve/priv/storage/<имя>.pw), поэтому ни разу не попадает в
    командную строку ssh, в вывод ошибок и в логи. Файл создаётся mktemp
    (случайное имя) в /dev/shm (tmpfs) или /tmp с правами 600 и удаляется
    после операции. В stdout печатается только путь к файлу либо маркер:
    PVEPBSNOPW — пароль не найден, PVEPBSERR:<шаг> — временный файл
    создать/записать не удалось.
    """
    st = shlex.quote(str(storage))
    return (
        "umask 077; "
        "d=/dev/shm; [ -d \"$d\" ] && [ -w \"$d\" ] || d=/tmp; "
        "t=$(mktemp \"$d/pbs-pw.XXXXXXXX\") || "
        "{ echo PVEPBSERR:mktemp; exit 0; }; "
        "v=$(awk -v S=" + st + " '"
        "/^[ \\t]/{ if (inb && $1 == \"password\") { l=$0; "
        "sub(/^[ \\t]*password[ \\t]*/, \"\", l); print l; exit } next } "
        "{ inb=0; i=index($0, \":\"); if (i>0) { t=substr($0,1,i-1); r=substr($0,i+1); "
        "gsub(/^[ \\t]+/, \"\", r); gsub(/[ \\t]+$/, \"\", r); "
        "inb=(t==\"pbs\" && r==S) } } "
        "' /etc/pve/storage.cfg 2>/dev/null); "
        "if [ -z \"$v\" ]; then "
        "f=/etc/pve/priv/storage/" + st + ".pw; "
        "if [ -r \"$f\" ] && [ -s \"$f\" ]; then "
        "v=$(sed -e '/^[[:space:]]*$/d' \"$f\" 2>/dev/null | tail -n 1); "
        "fi; fi; "
        "if [ -z \"$v\" ]; then rm -f -- \"$t\"; echo PVEPBSNOPW; exit 0; fi; "
        "printf '%s' \"$v\" > \"$t\" || "
        "{ rm -f -- \"$t\"; echo PVEPBSERR:write; exit 0; }; "
        "chmod 600 \"$t\" || "
        "{ rm -f -- \"$t\"; echo PVEPBSERR:chmod; exit 0; }; "
        "printf '%s\\n' \"$t\""
    )


def _pbs_prepare_password_file(cfg, storage):
    """Создаёт на ноде временный файл (права 600) с паролем PBS.

    Возвращает путь к файлу; вызывающий код (pbs_download_snapshot)
    удаляет его после операции — при успехе и при любой ошибке. Сам пароль
    не возвращается и нигде не логируется. Если временный файл создать
    невозможно, операция прерывается с понятной ошибкой — БЕЗ перехода
    к небезопасной передаче пароля через командную строку.
    """
    rc, out = ssh_run(cfg, _pbs_password_prepare_cmd(storage), check=False)
    if "PVEPBSNOPW" in out:
        raise BackupError(
            f"не найден пароль PBS-хранилища «{storage}»: на ноде нет файла "
            f"/etc/pve/priv/storage/{storage}.pw и в storage.cfg нет строки "
            "password. Задайте пароль хранилища в GUI (Datacenter → Storage → "
            "PBS) или впишите его в указанный файл (chmod 600)")
    marker = re.search(r"PVEPBSERR:(\S+)", out)
    if marker:
        raise BackupError(
            "не удалось подготовить временный файл для пароля PBS на ноде "
            f"(шаг: {marker.group(1)}; используются каталоги /dev/shm и /tmp). "
            "Пароль принципиально не передаётся через командную строку — "
            "операция прервана; проверьте наличие и права на /dev/shm и /tmp "
            "на ноде")
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if rc == 0 and lines and lines[-1].startswith("/"):
        pw_file = lines[-1]
        LOG.debug("Пароль PBS передаётся клиенту через временный файл %s "
                  "(права 600, удаляется после операции)", pw_file)
        return pw_file
    raise RemoteCommandError(
        "не удалось подготовить временный файл с паролем PBS на ноде "
        f"(код {rc}): {out.strip()[-200:] or 'нет вывода'}")


def _pbs_key_args(cfg, storage, params):
    """['--keyfile', путь] для хранилища с настроенным шифрованием, иначе [].

    Ориентир — параметр encryption-key в блоке хранилища в storage.cfg:
    само по себе наличие файла .enc шифрованием не считается. Ключ
    ожидается на ноде по пути /etc/pve/priv/storage/<имя>.enc (там его
    размещает PVE) и передаётся клиенту КАК ПУТЬ (--keyfile — штатный
    параметр proxmox-backup-client): содержимое ключа не копируется,
    не преобразовывается и не логируется. Файл ключа проверяется на
    существование, обычный файл, читаемость и непустоту (эквивалент
    test -f, test -r, test -s) ДО начала скачивания: при отсутствии,
    неверном типе файла, отсутствии прав на чтение или пустоте —
    понятная ошибка с указанием хранилища и пути; снапшот PBS не
    изменяется и не удаляется.
    """
    if not params.get("encryption-key"):
        return []
    key_path = f"/etc/pve/priv/storage/{storage}.enc"
    kp = shlex.quote(key_path)
    rc, out = ssh_run(cfg, (
        f"if [ ! -e {kp} ]; then echo PVEKEY:missing; "
        f"elif [ ! -f {kp} ]; then echo PVEKEY:notfile; "
        f"elif [ ! -r {kp} ]; then echo PVEKEY:noread; "
        f"elif [ ! -s {kp} ]; then echo PVEKEY:empty; "
        f"else echo PVEKEY:ok; fi"), check=False)
    marker = re.search(r"PVEKEY:(\S+)", out)
    verdict = marker.group(1) if marker else ""
    if verdict == "ok" and rc == 0:
        LOG.info("Хранилище «%s» настроено с шифрованием PBS: ключ %s "
                 "передаётся proxmox-backup-client (--keyfile)",
                 storage, key_path)
        return ["--keyfile", key_path]
    reason = {
        "missing": f"файл ключа {key_path} на ноде отсутствует",
        "notfile": f"{key_path} существует, но не является обычным файлом",
        "noread": f"нет прав на чтение файла ключа {key_path}",
        "empty": f"файл ключа {key_path} пуст",
    }.get(verdict)
    if reason:
        raise BackupError(
            f"для PBS-хранилища «{storage}» в storage.cfg задан параметр "
            f"encryption-key, но {reason}. Скачивание зашифрованных снапшотов "
            "без ключа невозможно; снапшот PBS не изменялся. Загрузите ключ "
            "в GUI (Datacenter → Storage → PBS → Encryption) или положите "
            "его по указанному пути (chmod 600)")
    raise BackupError(
        "не удалось проверить файл ключа шифрования PBS-хранилища "
        f"«{storage}» ({key_path}, код {rc}): "
        f"{out.strip()[-200:] or 'нет вывода'}")


def _pbs_env_prefix(params, pw_file):
    """Префикс 'env PBS_...' для запуска proxmox-backup-client на ноде.

    Пароль НЕ включается в префикс (и вообще ни в одну команду): клиент
    читает его из временного файла на ноде через PBS_PASSWORD_FILE —
    штатный механизм proxmox-backup-client. Так пароль не попадает
    в DEBUG-лог команд, в исключения и в вывод для пользователя.
    """
    repo = (f"{params.get('username') or 'root@pam'}"
            f"@{params['server']}:{params['datastore']}")
    pairs = [f"PBS_REPOSITORY={shlex.quote(repo)}",
             f"PBS_PASSWORD_FILE={shlex.quote(pw_file)}"]
    if params.get("fingerprint"):
        pairs.append(f"PBS_FINGERPRINT={shlex.quote(params['fingerprint'])}")
    if params.get("namespace"):
        pairs.append(f"PBS_NAMESPACE={shlex.quote(params['namespace'])}")
    return "env " + " ".join(pairs)


def _pbs_cleanup_temp(cfg, paths):
    """Удаляет временные ресурсы PBS на ноде; никогда не поднимает исключений.

    Вызывается из finally при любом завершении операции PBS. Ошибки очистки
    (недоступность ноды, неуспешное удаление) НЕ подменяют первоначальное
    исключение операции — они превращаются в предупреждение в логе.
    Удаление считается подтверждённым только после проверки фактического
    отсутствия каждого пути на ноде (rm + проверка [ -e ]/[ -L ]); если
    соединение не восстановилось или файлы остались, в логе явно говорится,
    что временные файлы могли остаться на узле Proxmox (с перечнем путей).
    Содержимое файлов не читается и не выводится — в сообщениях только пути;
    ни пароль, ни ключ шифрования в этих сообщениях не появляются.
    """
    paths = [p for p in paths if p]
    if not paths:
        return
    quoted = " ".join(shlex.quote(p) for p in paths)
    cmd = ("rm -rf -- " + quoted + " 2>/dev/null; echo PVECLNRC:$?; "
           "for p in " + quoted + "; do "
           "if [ -e \"$p\" ] || [ -L \"$p\" ]; then echo PVELEFT:$p; fi; done")
    try:
        rc, out = ssh_run(cfg, cmd, check=False)
    except BaseException as exc:               # нода недоступна и т.п.
        # Даже прерывание (KeyboardInterrupt) во время очистки не должно
        # подменять первоначальную ошибку операции — глотаем и логируем.
        LOG.warning(
            "Не удалось связаться с нодой для очистки временных файлов PBS "
            "(%s). Временные файлы могли остаться на узле Proxmox — при "
            "следующем подключении удалите их вручную: %s",
            exc, " ".join(paths))
        return
    left = re.findall(r"^PVELEFT:(.+)$", out, re.MULTILINE)
    if "PVECLNRC:" in out and not left:
        LOG.debug("Временные файлы PBS удалены с ноды, отсутствие "
                  "подтверждено: %s", " ".join(paths))
        return
    if left:
        LOG.warning(
            "Не удалось подтвердить удаление части временных файлов PBS: они "
            "могли остаться на узле Proxmox — удалите их вручную: %s",
            " ".join(left))
    else:
        LOG.warning(
            "Не удалось подтвердить удаление временных файлов PBS (код %s) — "
            "они могли остаться на узле Proxmox: %s", rc, " ".join(paths))


def pbs_download_snapshot(cfg, entry, dest_dir, storage):
    """Скачивает снапшот PBS на локальную машину.

    PBS-снапшот нельзя скачать как файл (это чанковые индексы fidx/didx,
    а не .vma.zst), поэтому: proxmox-backup-client на ноде восстанавливает
    все архивы снапшота во временный каталог, они упаковываются в tar,
    tar копируется scp и проверяется (SHA256 + структура). Результат —
    tar с восстановленными файлами снапшота (raw-образы, конфиги), а НЕ
    архив vzdump. Снапшот в PBS не удаляется никогда: жизненным циклом
    копий PBS управляют prune/GC, и автоматическое удаление могло бы
    разрушить цепочку инкрементальных копий.

    Безопасность: пароль PBS читается на ноде во временный файл (права
    600) и передаётся клиенту через PBS_PASSWORD_FILE — в командах
    и логах его нет; для зашифрованного хранилища клиенту передаётся
    ключ (--keyfile) с ноды. Файл пароля создаётся уже ВНУТРИ
    защищённого блока try/finally, поэтому при любой ошибке (даже сразу
    после его создания) попадает в процедуру очистки вместе со служебными
    каталогами ноды; очистка подтверждается проверкой отсутствия файлов,
    а её ошибки не подменяют первоначальное исключение.
    """
    volid = entry["volid"]
    pbs_check_client(cfg)
    params = read_pbs_storage_config(cfg, storage)
    snapshot = _pbs_snapshot_from_volid(volid)
    # Сначала — проверки, способные отказаться от операции ДО каких-либо
    # изменений и временных файлов: ключ шифрования.
    key_args = _pbs_key_args(cfg, storage, params)

    tmpdir = f"/tmp/pve-pbs-{os.getpid()}-{int(time.time())}"
    tarpath = f"{tmpdir}.tar"
    archive_name = _pbs_local_name(volid)
    local_tmp = dest_dir / f".tmp_{archive_name}"
    pw_file = ""      # путь появится сразу после создания файла пароля на ноде
    try:
        # Защищённый блок охватывает ВЕСЬ период после создания временного
        # файла пароля: подготовка параметров PBS, восстановление, упаковка,
        # передача и проверка выполняются ТОЛЬКО внутри него, чтобы при любой
        # ошибке finally включил файл пароля в процедуру очистки.
        pw_file = _pbs_prepare_password_file(cfg, storage)
        prefix = _pbs_env_prefix(params, pw_file)
        key_opts = "".join(" " + shlex.quote(arg) for arg in key_args)
        client = "proxmox-backup-client"
        LOG.info("Получение манифеста снапшота %s через proxmox-backup-client...",
                 snapshot)
        rc, out = ssh_run(cfg, f"{prefix} {client} restore "
                               f"{shlex.quote(snapshot)} index.json -{key_opts}",
                          check=False)
        if rc != 0:
            raise BackupError(
                f"не удалось получить манифест снапшота {snapshot} "
                f"(код {rc}): {out.strip()[-300:] or 'нет вывода'}. Если ошибка "
                "связана с аутентификацией — проверьте версию клиента на ноде "
                "(proxmox-backup-client version): механизм PBS_PASSWORD_FILE "
                "поддерживается начиная с proxmox-backup-client 2.x")
        try:
            files = json.loads(out.strip()).get("files") or []
        except (ValueError, AttributeError):
            raise BackupError(f"не удалось разобрать манифест снапшота {snapshot}")
        if not files:
            raise BackupError(f"манифест снапшота {snapshot} не содержит файлов")
        total = sum(int(item.get("size") or 0) for item in files)
        LOG.info("Снапшот %s: файлов %d, суммарный логический размер %s",
                 snapshot, len(files), human_size(total))

        ssh_run(cfg, f"mkdir -p -- {shlex.quote(tmpdir)}")
        for item in files:
            fname = str(item.get("filename") or "")
            if not fname or fname.startswith(".") or "/" in fname:
                raise BackupError(
                    "подозрительное имя файла в манифесте снапшота: "
                    f"{fname!r}")
            if fname.endswith(".pxar") or fname.endswith(".pxar.didx"):
                target = f"{tmpdir}/" + re.sub(r"\.pxar(\.didx)?$", "", fname)
            else:
                target = f"{tmpdir}/" + re.sub(r"\.(fidx|didx|blob)$", "", fname)
            rc, out = ssh_run(cfg, f"{prefix} {client} restore "
                                   f"{shlex.quote(snapshot)} "
                                   f"{shlex.quote(fname)} {shlex.quote(target)}"
                                   f"{key_opts}",
                              check=False)
            if rc != 0:
                raise BackupError(
                    f"не удалось восстановить {fname} из снапшота {snapshot} "
                    f"(код {rc}): {out.strip()[-300:]}")
        ssh_run(cfg, f"tar -C {shlex.quote(tmpdir)} -cf {shlex.quote(tarpath)} .")
        remote_sum = remote_sha256(cfg, tarpath)
        LOG.info("SHA256 tar-архива на сервере: %s", remote_sum)
        try:
            LOG.info("Копирование по сети (scp)...")
            rc, out = scp_pull(cfg, tarpath, local_tmp)
            if rc != 0:
                tail = out.strip().replace("\r", " ").splitlines()[-3:]
                raise BackupError(
                    f"scp завершился с кодом {rc}: {' | '.join(tail)}")
            if local_sha256(local_tmp) != remote_sum:
                raise BackupError(
                    "контрольные суммы не совпали — временный файл удалён, "
                    "снапшот PBS сохранён")
            target_path = (dest_dir / archive_name
                           if not (dest_dir / archive_name).exists()
                           else _free_destination_path(dest_dir, archive_name))
            os.replace(local_tmp, target_path)
        finally:
            try:
                local_tmp.unlink(missing_ok=True)
            except OSError as exc:
                LOG.warning("Не удалось удалить локальный временный файл %s: %s",
                            local_tmp, exc)
        ok, struct_detail = verify_archive_structure(target_path)
        if not ok:
            target_path.unlink(missing_ok=True)
            raise BackupError(
                f"структура tar-архива повреждена ({struct_detail}) — локальная "
                f"копия удалена, снапшот PBS сохранён")
        LOG.info("Структура архива: %s", struct_detail)
        LOG.info("Снапшот PBS остаётся на сервере: delete_after_download к PBS "
                 "не применяется (удаление снапшотов выполняется политиками "
                 "prune/GC на PBS)")
        size = target_path.stat().st_size
        return DownloadResult(volid, True,
                              f"{target_path.name} ({human_size(size)})",
                              local_name=target_path.name, size=size)
    finally:
        # Очистка всех созданных временных ресурсов ноды (временный каталог,
        # tar-архив, файл пароля — что уже успело создаться) при любом
        # завершении операции: успехе и любой ошибке. _pbs_cleanup_temp
        # не поднимает исключений, поэтому ошибки очистки (в том числе
        # недоступность ноды) не подменяют первоначальное исключение.
        _pbs_cleanup_temp(cfg, [tmpdir, tarpath, pw_file])
