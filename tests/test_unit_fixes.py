#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit-тесты точечных доработок Proxmox Backup Script (без сети, на моках).

Покрывают:
  1) надёжную очистку временных файлов PBS (не маскирует исходную ошибку,
     подтверждает удаление, файл пароля попадает в очистку при любом сбое);
  2) проверку файла ключа шифрования (эквивалент test -f / -r / -s,
     отказ ДО начала скачивания);
  3) разбор pvesm status по заголовку: отсутствующий/нечитаемый Available —
     «неизвестно», а не 0; резервный разбор — с предупреждением;
  4) регресс отображения LXC: «-» в столбце Lock не попадает в имя.

Запуск: python3 tests/test_unit_fixes.py
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import BackupError, RemoteCommandError             # noqa: E402
from proxmox import guests as pve_guests                      # noqa: E402
from storage import discovery as pve_discovery                # noqa: E402
from storage import pbs as pve_pbs                            # noqa: E402
from transfer import verify as pve_verify                     # noqa: E402

# После реструктуризации функции живут в модулях по назначению, поэтому
# патчи применяются к модулю, где функция ОПРЕДЕЛЕНА (иначе подмена
# не сработала бы); сами проверки не менялись.

MANIFEST = {"backup-type": "vm", "backup-id": "105",
            "backup-time": 1735000000,
            "files": [{"filename": "qemu-server.conf.blob", "size": 288},
                      {"filename": "drive-scsi0.img.fidx", "size": 34603008}]}
SHA = "a" * 64
PW_FILE = "/dev/shm/pbs-pw.UNITTEST"
KEY_PATH = "/etc/pve/priv/storage/pbs1.enc"

PVESM_STD = (
    "Name             Type     Status           Total            Used"
    "       Available        %\n"
    "local            dir      active       1000000000       500000000"
    "       500000000       50.00%\n"
    "local-lvm        lvmthin  active       1000000000       100000000"
    "       900000000       10.00%\n"
)
PVESM_NO_HEADER = (
    "local            dir      active       1000000000       500000000"
    "       500000000       50.00%\n"
    "local-lvm        lvmthin  active       1000000000       100000000"
    "       900000000       10.00%\n"
    "broken-garbage-row\n"
)
PVESM_NO_AVAIL = (
    "Name             Type     Status           Total            Used       %\n"
    "local            dir      active       1000000000       500000000"
    "   50.00%\n"
    "local-lvm        lvmthin  active       1000000000       100000000"
    "   10.00%\n"
)
PVESM_BAD_AVAIL = (
    "Name             Type     Status           Total            Used"
    "       Available        %\n"
    "weird            dir      active       1000       500"
    "       n/a       50.00%\n"
)
PVESM_ZERO_AVAIL = (
    "Name             Type     Status           Total            Used"
    "       Available        %\n"
    "full             dir      active       1000       1000"
    "       0       100.00%\n"
)


def make_cfg(**backup_over):
    backup = {"storage": "pbs1", "mode": "snapshot", "compress": "zstd",
              "destination": "./backups", "delete_after_download": True}
    backup.update(backup_over)
    return {"proxmox": {"host": "node", "port": 22, "user": "root",
                        "key_file": "", "password": "", "ssh_timeout": 0,
                        "_password": None},
            "backup": backup,
            "vms": {"include": [], "exclude": []},
            "logging": {"dir": "./logs", "console_level": "INFO",
                        "file_level": "DEBUG"}}


def ssh_stub(outputs):
    """ssh_run-заглушка: prefix -> (rc, out)."""
    def run(cfg, cmd, check=True, passthrough=False):
        for prefix, result in outputs.items():
            if cmd.startswith(prefix):
                return result
        return 0, ""
    return run


# ---------------------------------------------------------------------------
# §2.4 Определение свободного места (pvesm status)
# ---------------------------------------------------------------------------

class GetStoragesTests(unittest.TestCase):

    def run_get_storages(self, out):
        with mock.patch.object(pve_discovery, "ssh_run", ssh_stub(
                {"pvesm status": (0, out)})):
            return pve_discovery.get_storages(make_cfg())

    def test_header_with_available(self):
        storages = self.run_get_storages(PVESM_STD)
        by_name = {s["name"]: s for s in storages}
        self.assertEqual(by_name["local"]["avail"], 500000000)
        self.assertEqual(by_name["local-lvm"]["avail"], 900000000)
        self.assertEqual(by_name["local"]["type"], "dir")
        self.assertEqual(by_name["local-lvm"]["type"], "lvmthin")
        self.assertEqual(by_name["local"]["status"], "active")
        self.assertEqual(by_name["local"]["total"], 1000000000)

    def test_header_without_available_marks_unknown(self):
        with self.assertLogs(pve_discovery.LOG, level="WARNING") as captured:
            storages = self.run_get_storages(PVESM_NO_AVAIL)
        by_name = {s["name"]: s for s in storages}
        self.assertIsNone(by_name["local"]["avail"])       # не 0!
        self.assertIsNone(by_name["local-lvm"]["avail"])
        # остальные столбцы продолжают определяться
        self.assertEqual(by_name["local"]["type"], "dir")
        self.assertEqual(by_name["local"]["status"], "active")
        self.assertEqual(by_name["local"]["total"], 1000000000)
        messages = " ".join(r.getMessage() for r in captured.records)
        self.assertIn("нет столбца Available", messages)

    def test_no_header_fallback_warns(self):
        with self.assertLogs(pve_discovery.LOG, level="WARNING") as captured:
            storages = self.run_get_storages(PVESM_NO_HEADER)
        by_name = {s["name"]: s for s in storages}
        self.assertEqual(by_name["local"]["avail"], 500000000)
        self.assertEqual(by_name["local-lvm"]["avail"], 900000000)
        messages = " ".join(r.getMessage() for r in captured.records)
        self.assertIn("резервный разбор", messages)

    def test_bad_available_value_is_unknown_not_zero(self):
        with self.assertLogs(pve_pbs.LOG, level="WARNING") as captured:
            storages = self.run_get_storages(PVESM_BAD_AVAIL)
        by_name = {s["name"]: s for s in storages}
        self.assertIsNone(by_name["weird"]["avail"])       # не 0!
        self.assertEqual(by_name["weird"]["type"], "dir")
        self.assertEqual(by_name["weird"]["status"], "active")
        messages = " ".join(r.getMessage() for r in captured.records)
        self.assertIn("не удалось разобрать свободное место", messages)
        self.assertIn("weird", messages)

    def test_zero_available_is_valid_zero(self):
        storages = self.run_get_storages(PVESM_ZERO_AVAIL)
        self.assertEqual(storages[0]["avail"], 0)          # достоверный ноль

    def test_garbage_row_skipped_without_crash(self):
        storages = self.run_get_storages(PVESM_NO_HEADER)
        self.assertEqual({s["name"] for s in storages},
                         {"local", "local-lvm"})


# ---------------------------------------------------------------------------
# §2.3 Проверка файла ключа шифрования PBS
# ---------------------------------------------------------------------------

class KeyCheckTests(unittest.TestCase):

    def run_key_args(self, rc, out, params=None):
        params = params if params is not None else {
            "server": "pbs:8007", "datastore": "ds", "encryption-key": KEY_PATH}
        calls = []

        def recorder(cfg, cmd, check=True, passthrough=False):
            calls.append(cmd)
            return rc, out

        with mock.patch.object(pve_pbs, "ssh_run", recorder):
            result = pve_pbs._pbs_key_args(make_cfg(), "pbs1", params)
        return result, calls

    def test_key_ok_returns_keyfile(self):
        result, calls = self.run_key_args(0, "PVEKEY:ok\n")
        self.assertEqual(result, ["--keyfile", KEY_PATH])
        self.assertEqual(len(calls), 1)
        # проверка эквивалентна test -f / test -r / test -s
        self.assertIn("[ ! -e ", calls[0])
        self.assertIn("[ ! -f ", calls[0])
        self.assertIn("[ ! -r ", calls[0])
        self.assertIn("[ ! -s ", calls[0])

    def test_key_missing_stops(self):
        with self.assertRaises(BackupError) as cm:
            self.run_key_args(0, "PVEKEY:missing\n")
        text = str(cm.exception)
        self.assertIn("pbs1", text)
        self.assertIn(KEY_PATH, text)
        self.assertIn("отсутствует", text)
        self.assertIn("снапшот PBS не изменялся", text)

    def test_key_not_regular_file_stops(self):
        with self.assertRaises(BackupError) as cm:
            self.run_key_args(0, "PVEKEY:notfile\n")
        self.assertIn("не является обычным файлом", str(cm.exception))
        self.assertIn(KEY_PATH, str(cm.exception))

    def test_key_unreadable_stops(self):
        with self.assertRaises(BackupError) as cm:
            self.run_key_args(0, "PVEKEY:noread\n")
        self.assertIn("нет прав на чтение", str(cm.exception))
        self.assertIn(KEY_PATH, str(cm.exception))

    def test_key_empty_stops(self):
        with self.assertRaises(BackupError) as cm:
            self.run_key_args(0, "PVEKEY:empty\n")
        self.assertIn("пуст", str(cm.exception))
        self.assertIn(KEY_PATH, str(cm.exception))

    def test_check_failure_unparseable_output_stops(self):
        with self.assertRaises(BackupError) as cm:
            self.run_key_args(1, "")
        self.assertIn("не удалось проверить файл ключа", str(cm.exception))

    def test_no_encryption_configured_no_check(self):
        result, calls = self.run_key_args(
            0, "", params={"server": "pbs:8007", "datastore": "ds"})
        self.assertEqual(result, [])
        self.assertEqual(calls, [])            # команда проверки не выполнялась


# ---------------------------------------------------------------------------
# §2.1 Очистка временных файлов PBS
# ---------------------------------------------------------------------------

class CleanupHelperTests(unittest.TestCase):

    TMP = "/tmp/pve-pbs-1-1000"
    TAR = "/tmp/pve-pbs-1-1000.tar"

    def run_cleanup(self, rc, out, raise_exc=None, paths=None):
        paths = paths or [self.TMP, self.TAR, PW_FILE]
        with mock.patch.object(pve_pbs, "ssh_run",
                               mock.Mock(side_effect=raise_exc, return_value=(rc, out))) as run, \
             mock.patch.object(pve_pbs.LOG, "warning") as warn, \
             mock.patch.object(pve_pbs.LOG, "debug") as dbg:
            pve_pbs._pbs_cleanup_temp(make_cfg(), paths)
        return run, warn, dbg

    def test_confirmed_cleanup_no_warning(self):
        run, warn, _ = self.run_cleanup(0, "PVECLNRC:0\n")
        cmd = run.call_args[0][1]
        self.assertIn("PVECLNRC", cmd)
        for path in (self.TMP, self.TAR, PW_FILE):
            self.assertIn(path, cmd)
        warn.assert_not_called()               # успех — без предупреждений

    def test_ssh_failure_does_not_raise_and_warns(self):
        failure = RemoteCommandError("ssh: connect: Connection refused")
        _, warn, _ = self.run_cleanup(0, "", raise_exc=failure)
        self.assertEqual(warn.call_count, 1)
        message = " ".join(str(a) for a in warn.call_args[0])
        self.assertIn("могли остаться", message)
        self.assertIn(self.TMP, message)
        self.assertIn(PW_FILE, message)

    def test_leftover_files_warn(self):
        _, warn, _ = self.run_cleanup(0, f"PVECLNRC:0\nPVELEFT:{self.TMP}\n")
        self.assertEqual(warn.call_count, 1)
        message = " ".join(str(a) for a in warn.call_args[0])
        self.assertIn(self.TMP, message)
        self.assertIn("могли остаться", message)

    def test_unconfirmed_output_warns(self):
        _, warn, _ = self.run_cleanup(1, "")   # нет маркеров — не подтверждено
        self.assertEqual(warn.call_count, 1)
        message = " ".join(str(a) for a in warn.call_args[0])
        self.assertIn("Не удалось подтвердить удаление", message)

    def test_empty_paths_no_ssh(self):
        with mock.patch.object(pve_pbs, "ssh_run") as run:
            pve_pbs._pbs_cleanup_temp(make_cfg(), ["", ""])
        run.assert_not_called()


# ---------------------------------------------------------------------------
# §2.1/§2.2/§2.3 Сквозной сценарий pbs_download_snapshot на моках
# ---------------------------------------------------------------------------

class PbsDownloadTests(unittest.TestCase):

    def setUp(self):
        self.dest = Path(tempfile.mkdtemp(prefix="pve-unit-"))

    def dispatcher(self, *, key_verdict="ok", key_rc=0, manifest_rc=0,
                   restore_rc=0, tar_rc=0, cleanup_rc=0,
                   cleanup_out="PVECLNRC:0\n", cleanup_raise=None):
        calls = []

        def run(cfg, cmd, check=True, passthrough=False):
            calls.append(cmd)
            if cmd.startswith("if [ ! -e "):
                rc, out = key_rc, f"PVEKEY:{key_verdict}\n"
            elif cmd.startswith("umask 077;"):
                rc, out = 0, PW_FILE + "\n"
            elif "proxmox-backup-client restore" in cmd:
                if "index.json" in cmd:
                    rc, out = ((manifest_rc, "fake: manifest restore failed")
                               if manifest_rc != 0
                               else (0, json.dumps(MANIFEST)))
                else:
                    rc, out = ((restore_rc, "fake: file restore failed")
                               if restore_rc != 0 else (0, ""))
            elif cmd.startswith("mkdir "):
                rc, out = 0, ""
            elif cmd.startswith("tar "):
                rc, out = tar_rc, "" if tar_rc == 0 else "tar: fake error"
            elif cmd.startswith("sha256sum"):
                rc, out = 0, f"{SHA}  /tmp/pve-pbs-x.tar"
            elif "PVECLNRC" in cmd:
                if cleanup_raise is not None:
                    raise cleanup_raise
                rc, out = cleanup_rc, cleanup_out
            else:
                rc, out = 0, ""
            if check and rc != 0:              # как реальный ssh_run
                raise RemoteCommandError(
                    f"ошибка выполнения на ноде (код {rc}): {cmd}\n{out}")
            return rc, out

        return run, calls

    def run_pbs(self, run, *, params=None, scp_rc=0, local_sum=SHA,
                struct_ok=True):
        params = params if params is not None else {
            "server": "pbs.example:8007", "datastore": "store1",
            "username": "root@pam"}
        entry = {"volid": "pbs1:backup/vm/105/2025-12-31T22:00:00Z"}
        cfg = make_cfg()

        def fake_scp(cfg_, remote, local):
            Path(local).write_bytes(b"tar-data")
            return scp_rc, "" if scp_rc == 0 else "scp: network failure"

        with mock.patch.object(pve_pbs, "ssh_run", run), \
             mock.patch.object(pve_verify, "ssh_run", run), \
             mock.patch.object(pve_pbs, "pbs_check_client", lambda c: None), \
             mock.patch.object(pve_pbs, "read_pbs_storage_config",
                               lambda c, s: dict(params)), \
             mock.patch.object(pve_pbs, "scp_pull", fake_scp), \
             mock.patch.object(pve_pbs, "local_sha256",
                               lambda p, bufsize=1024 * 1024: local_sum), \
             mock.patch.object(pve_pbs, "verify_archive_structure",
                               lambda p: (struct_ok, "tar-архив читается")):
            result = pve_pbs.pbs_download_snapshot(cfg, entry, self.dest, "pbs1")
        return result

    def cleanup_calls(self, calls):
        return [c for c in calls if "PVECLNRC" in c]

    # --- успешное завершение: все временные файлы удалены ------------------

    def test_success_cleanup_covers_all_temps(self):
        run, calls = self.dispatcher()
        with mock.patch.object(pve_pbs.LOG, "warning") as warn:
            result = self.run_pbs(run)
        self.assertTrue(result.ok)
        cleanup = self.cleanup_calls(calls)
        self.assertEqual(len(cleanup), 1)
        self.assertIn(PW_FILE, cleanup[0])     # файл пароля в очистке
        self.assertIn("/tmp/pve-pbs-", cleanup[0])
        self.assertIn(".tar", cleanup[0])
        warn.assert_not_called()

    def test_error_right_after_pw_creation_cleans_pw_file(self):
        run, calls = self.dispatcher(manifest_rc=1)   # падение сразу после pw
        with self.assertRaises(BackupError) as cm:
            self.run_pbs(run)
        self.assertIn("манифест", str(cm.exception))   # исходная ошибка жива
        cleanup = self.cleanup_calls(calls)
        self.assertEqual(len(cleanup), 1)
        self.assertIn(PW_FILE, cleanup[0])     # созданный файл попал в очистку

    def test_restore_error_cleanup(self):
        run, calls = self.dispatcher(restore_rc=1)
        with self.assertRaises(BackupError) as cm:
            self.run_pbs(run)
        self.assertIn("восстановить", str(cm.exception))
        cleanup = self.cleanup_calls(calls)
        self.assertEqual(len(cleanup), 1)
        self.assertIn(PW_FILE, cleanup[0])

    def test_tar_error_cleanup(self):
        run, calls = self.dispatcher(tar_rc=1)
        with self.assertRaises(BackupError) as cm:
            self.run_pbs(run)
        self.assertIn("tar", str(cm.exception))
        cleanup = self.cleanup_calls(calls)
        self.assertEqual(len(cleanup), 1)
        self.assertIn(PW_FILE, cleanup[0])

    def test_scp_error_cleanup(self):
        run, calls = self.dispatcher()
        with self.assertRaises(BackupError) as cm:
            self.run_pbs(run, scp_rc=1)
        self.assertIn("scp завершился с кодом 1", str(cm.exception))
        cleanup = self.cleanup_calls(calls)
        self.assertEqual(len(cleanup), 1)
        self.assertIn(PW_FILE, cleanup[0])
        # локальный временный файл тоже удалён
        self.assertEqual(list(self.dest.glob(".tmp_*")), [])

    def test_sha_mismatch_cleanup(self):
        run, calls = self.dispatcher()
        with self.assertRaises(BackupError) as cm:
            self.run_pbs(run, local_sum="b" * 64)
        self.assertIn("контрольные суммы", str(cm.exception))
        cleanup = self.cleanup_calls(calls)
        self.assertEqual(len(cleanup), 1)
        self.assertIn(PW_FILE, cleanup[0])

    def test_cleanup_ssh_failure_does_not_mask_original_error(self):
        failure = RemoteCommandError("ssh: connect: Connection refused")
        run, _ = self.dispatcher(manifest_rc=1, cleanup_raise=failure)
        with self.assertLogs(pve_pbs.LOG, level="WARNING") as captured, \
             self.assertRaises(BackupError) as cm:
            self.run_pbs(run)
        # исходная ошибка не замаскирована ошибкой очистки
        self.assertIn("манифест", str(cm.exception))
        self.assertNotIn("Connection refused", str(cm.exception))
        messages = " ".join(r.getMessage() for r in captured.records)
        self.assertIn("могли остаться", messages)
        self.assertIn(PW_FILE, messages)

    def test_cleanup_ssh_failure_on_success_path_keeps_result(self):
        failure = RemoteCommandError("ssh: connect: Connection refused")
        run, _ = self.dispatcher(cleanup_raise=failure)
        with self.assertLogs(pve_pbs.LOG, level="WARNING") as captured:
            result = self.run_pbs(run)
        self.assertTrue(result.ok)             # загрузка успешна
        messages = " ".join(r.getMessage() for r in captured.records)
        self.assertIn("могли остаться", messages)

    def test_leftover_files_on_cleanup_warns(self):
        run, _ = self.dispatcher(
            cleanup_out=f"PVECLNRC:0\nPVELEFT:{PW_FILE}\n")
        with self.assertLogs(pve_pbs.LOG, level="WARNING") as captured:
            result = self.run_pbs(run)
        self.assertTrue(result.ok)
        messages = " ".join(r.getMessage() for r in captured.records)
        self.assertIn("могли остаться", messages)
        self.assertIn(PW_FILE, messages)

    # --- передача --keyfile во все вызовы восстановления -------------------

    def test_keyfile_passed_to_all_restore_calls(self):
        params = {"server": "pbs.example:8007", "datastore": "store1",
                  "username": "root@pam", "encryption-key": KEY_PATH}
        run, calls = self.dispatcher(key_verdict="ok")
        result = self.run_pbs(run, params=params)
        self.assertTrue(result.ok)
        restores = [c for c in calls if "proxmox-backup-client restore" in c]
        self.assertGreaterEqual(len(restores), 3)      # манифест + 2 файла
        for cmd in restores:
            self.assertIn("--keyfile", cmd)
            self.assertIn(KEY_PATH, cmd)

    def test_no_encryption_no_key_check_command(self):
        run, calls = self.dispatcher()
        result = self.run_pbs(run)
        self.assertTrue(result.ok)
        self.assertEqual([c for c in calls if c.startswith("if [ ! -e ")], [])
        restores = [c for c in calls if "proxmox-backup-client restore" in c]
        for cmd in restores:
            self.assertNotIn("--keyfile", cmd)


# ---------------------------------------------------------------------------
# Регресс: LXC и «-» в столбце Lock (не должно попадать в имя)
# ---------------------------------------------------------------------------

class GuestListTests(unittest.TestCase):

    def run_guests(self, qm_out, pct_out):
        with mock.patch.object(pve_guests, "ssh_run", ssh_stub(
                {"qm list": (0, qm_out), "pct list": (0, pct_out)})):
            return pve_guests.get_node_guests(make_cfg())

    def test_pct_dash_lock_not_in_name(self):
        guests = self.run_guests(
            "VMID NAME STATUS MEM(MB) BOOTDISK(GB) PID\n"
            " 100 web01 running 2048 32.00 1000\n",
            "VMID Status Lock Name\n"
            "202 running - multi word ct\n")
        ct = [g for g in guests if g["vmid"] == 202][0]
        self.assertEqual(ct["gtype"], "lxc")
        self.assertEqual(ct["status"], "running")
        self.assertEqual(ct["name"], "multi word ct")   # без ведущего «-»

    def test_pct_known_lock_stripped(self):
        guests = self.run_guests(
            "VMID NAME STATUS MEM(MB) BOOTDISK(GB) PID\n",
            "VMID Status Lock Name\n"
            "201 stopped backup ct-db\n")
        ct = guests[0]
        self.assertEqual(ct["status"], "stopped")
        self.assertEqual(ct["name"], "ct-db")

    def test_qemu_rows_parsed(self):
        guests = self.run_guests(
            "VMID NAME STATUS MEM(MB) BOOTDISK(GB) PID\n"
            " 100 web01 running 2048 32.00 1000\n"
            " 101 db01 stopped 4096 64.00 0\n",
            "VMID Status Lock Name\n")
        self.assertEqual([(g["vmid"], g["name"], g["gtype"]) for g in guests],
                         [(100, "web01", "qemu"), (101, "db01", "qemu")])


if __name__ == "__main__":
    unittest.main(verbosity=2)
