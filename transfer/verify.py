# -*- coding: utf-8 -*-
"""Проверка полученных файлов: SHA256 и структура архива.

Перенесено из proxmox_backup.py v5 без изменений: алгоритмы вычисления
и сравнения контрольных сумм, разбор вывода sha256sum на ноде, проверка
структуры (сигнатур форматов vzdump: VMA/tar/gzip/zstd/lzop) сохранены.
"""

import gzip
import hashlib
import re
import shlex
import tarfile

from common import RemoteCommandError
from proxmox.ssh import ssh_run

# Сигнатуры форматов vzdump — для проверки структуры скачанного архива
VMA_MAGIC = b"VMA\x00"                    # образ VMA (ВМ, без сжатия)
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"         # поток zstd
LZO_MAGIC = b"\x89LZO\x00\r\n\x1a\n"     # поток lzop


def local_sha256(path, bufsize=1024 * 1024):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(bufsize), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_archive_structure(path):
    """Проверяет структуру (сигнатуры) скачанного архива vzdump.

    SHA256 подтверждает только совпадение копии с оригиналом по сети;
    эта проверка дополнительно удостоверяется, что файл похож на архив
    нужного формата. Потоки zstd/lzo стандартная библиотека не распаковывает
    — для них проверяется сигнатура; окончательная гарантия восстанавливаемости
    достигается только периодическим тестовым восстановлением.
    Возвращает (ok, пояснение).
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        return False, f"нет доступа к файлу: {exc}"
    if size == 0:
        return False, "файл пуст"
    name = path.name.lower()
    try:
        if name.endswith((".vma.zst", ".tar.zst")):
            with open(path, "rb") as fh:
                if fh.read(4) != ZSTD_MAGIC:
                    return False, "нет сигнатуры zstd-потока"
            return True, "сигнатура zstd корректна"
        if name.endswith((".vma.lzo", ".tar.lzo")):
            with open(path, "rb") as fh:
                if fh.read(9) != LZO_MAGIC:
                    return False, "нет сигнатуры lzop-потока"
            return True, "сигнатура lzop корректна"
        if name.endswith((".vma.gz", ".tar.gz", ".tgz")):
            with gzip.open(path, "rb") as fh:
                magic = fh.read(4)
            if magic == VMA_MAGIC:
                return True, "gzip-поток с архивом VMA"
            with tarfile.open(path, "r:gz") as tf:
                if tf.next() is None:
                    return False, "gzip-поток не содержит данных tar"
            return True, "gzip-поток с tar-архивом"
        if name.endswith(".vma"):
            with open(path, "rb") as fh:
                if fh.read(4) != VMA_MAGIC:
                    return False, "нет сигнатуры VMA"
            return True, "сигнатура VMA корректна"
        if name.endswith(".tar"):
            with tarfile.open(path, "r:") as tf:
                if tf.next() is None:
                    return False, "пустой tar-архив"
            return True, "tar-архив читается"
    except (OSError, EOFError, tarfile.TarError) as exc:
        return False, f"файл не читается как архив: {exc}"
    return True, "неизвестный формат — структура не проверялась"


def remote_sha256(cfg, remote_path):
    rc, out = ssh_run(cfg, f"sha256sum -- {shlex.quote(remote_path)}")
    match = re.search(r"\b[0-9a-f]{64}\b", out)
    if not match:
        raise RemoteCommandError(
            f"не удалось разобрать вывод sha256sum для {remote_path}: "
            f"{out.strip()[:200]}")
    return match.group(0)
