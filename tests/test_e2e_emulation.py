#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""E2E-проверка proxmox_backup.py на эмуляции ноды (fake ssh/scp, без сети).

Скрипт запускается как реальный процесс; все команды «ноды» обслуживают
подменные ssh/scp из tests/fakepve. Проверяются:

  * отсутствие регрессий обычного конвейера vzdump (ВМ + LXC);
  * скачивание PBS-снапшотов без шифрования и с шифрованием (--keyfile
    во всех вызовах proxmox-backup-client);
  * отказ ДО скачивания при отсутствующем/непустом/нечитаемом/не-файле
    ключе шифрования (и отсутствие временных файлов в этих случаях);
  * очистка временных файлов ноды при ошибках restore/tar/scp;
  * отсутствие паролей и содержимого ключей в логах;
  * «неизвестное» свободное место при отсутствии столбца Available.

Запуск: python3 tests/test_e2e_emulation.py
"""
import glob
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
FAKEPVE = Path(__file__).resolve().parent / "fakepve"
KEY_BYTES = b"UNITTEST-KEY-BYTES-0123456789abcdef"

# секреты, которые НЕ должны попасть ни в один лог
SECRETS = ("fake-pbs-password", KEY_BYTES.decode())


class E2EBase(unittest.TestCase):

    def setUp(self):
        for name in ("ssh", "scp"):
            (FAKEPVE / name).chmod(0o755)
        self.work = Path(tempfile.mkdtemp(prefix="pve-e2e-"))
        self.node = self.work / "node"
        self.node.mkdir()
        self.dest = self.work / "backups"
        self.logs = self.work / "logs"
        self.env = dict(os.environ)
        self.env["FAKE_PVE_DIR"] = str(self.node)
        self.env["PATH"] = f"{FAKEPVE}{os.pathsep}{self.env.get('PATH', '')}"
        self.write_storage_cfg("")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.work, ignore_errors=True)
        # подчищаем файлы, которые тест мог НАМЕРЕННО оставить на «ноде»
        # (FAKE_RM_FAIL), чтобы они не мешали другим тестам
        for path in (glob.glob("/dev/shm/pbs-pw.*") + glob.glob("/tmp/pbs-pw.*")
                     + glob.glob("/tmp/pve-pbs-*")):
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    # --- подготовка «ноды» и конфига ---------------------------------------

    def write_storage_cfg(self, pbs_extra):
        cfg = "dir: local\n    path /var/lib/vz\n    content backup\n\n"
        if pbs_extra is not None:
            cfg += ("pbs: pbs1\n    server pbs.example:8007\n"
                    "    datastore store1\n    username root@pam\n"
                    + pbs_extra)
        (self.node / "storage.cfg").write_text(cfg, encoding="utf-8")

    def write_config(self, storage="local"):
        cfg = (
            "PROXMOX = {'host': 'fakepve', 'port': 22, 'user': 'root',\n"
            "           'key_file': '', 'password': '', 'ssh_timeout': 0}\n"
            "BACKUP = {'storage': '%s', 'mode': 'snapshot', 'compress': 'zstd',\n"
            "          'destination': r'%s', 'delete_after_download': True}\n"
            "VMS = {'include': [], 'exclude': []}\n"
            "LOGGING = {'dir': r'%s', 'console_level': 'INFO',\n"
            "           'file_level': 'DEBUG'}\n"
            % (storage, self.dest, self.logs)
        )
        (self.work / "backup_config.py").write_text(cfg, encoding="utf-8")

    # --- запуск и проверки --------------------------------------------------

    def run_script(self, args, stdin="", **extra_env):
        env = dict(self.env)
        env.update({k: v for k, v in extra_env.items() if v is not None})
        return subprocess.run(
            [sys.executable, str(PROJECT / "proxmox_backup.py")] + args,
            input=stdin, capture_output=True, text=True, env=env,
            cwd=self.work, timeout=180)

    def read_log(self):
        logs = sorted(self.logs.glob("backup_*.log"))
        self.assertTrue(logs, "лог-файл не создан")
        return "\n".join(p.read_text(encoding="utf-8") for p in logs)

    def assert_no_secrets(self, proc):
        for text in (self.read_log(), proc.stdout, proc.stderr):
            for secret in SECRETS:
                self.assertNotIn(secret, text)

    def assert_no_password_env(self, proc):
        for text in (self.read_log(), proc.stdout, proc.stderr):
            # PBS_PASSWORD_FILE=<путь> разрешён; PBS_PASSWORD='...' — нет
            self.assertIsNone(re.search(r"PBS_PASSWORD=(?!_FILE)", text),
                              "пароль PBS попал в вывод/лог")

    def assert_no_node_tempfiles(self):
        leftovers = (glob.glob("/dev/shm/pbs-pw.*") + glob.glob("/tmp/pbs-pw.*")
                     + glob.glob("/tmp/pve-pbs-*"))
        self.assertEqual(leftovers, [], f"остались временные файлы: {leftovers}")

    def client_calls(self):
        log = self.node / "pbs-client-calls.log"
        if not log.exists():
            return []
        return [line for line in
                log.read_text(encoding="utf-8").splitlines() if line.strip()]

    def make_key_file(self, content=KEY_BYTES):
        priv = self.node / "priv" / "storage"
        priv.mkdir(parents=True, exist_ok=True)
        (priv / "pbs1.enc").write_bytes(content)


# ---------------------------------------------------------------------------
# Регресс обычного конвейера vzdump (не должен быть затронут доработками)
# ---------------------------------------------------------------------------

class VzdumpRegressionTests(E2EBase):

    def test_full_vzdump_run_qemu_and_lxc(self):
        self.write_config("local")
        proc = self.run_script([])
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Успешно: 6/6", self.read_log())
        files = sorted(p.name for p in self.dest.iterdir())
        self.assertEqual(len(files), 6)
        self.assertEqual(sum(1 for f in files if f.endswith(".vma.zst")), 3)
        self.assertEqual(sum(1 for f in files if f.endswith(".tar.zst")), 3)
        # архивы удалены с сервера после проверки (delete_after_download=True)
        dump = self.node / "dump"
        self.assertEqual([p for p in dump.iterdir() if p.is_file()], [],
                         "на сервере остались архивы после успешного скачивания")
        self.assert_no_secrets(proc)
        self.assert_no_password_env(proc)
        self.assert_no_node_tempfiles()


# ---------------------------------------------------------------------------
# PBS без шифрования и с шифрованием
# ---------------------------------------------------------------------------

class PbsDownloadTests(E2EBase):

    def test_pbs_unencrypted_download_and_cleanup(self):
        self.write_config("pbs1")
        proc = self.run_script(["--download-existing"], stdin="1\n",
                               FAKE_PBS_STORAGE="1")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        downloaded = [p.name for p in self.dest.iterdir()]
        self.assertEqual(downloaded,
                         ["pbs-ct-200-2025-12-30T22-00-00Z.tar"])
        calls = self.client_calls()
        self.assertGreaterEqual(len(calls), 3)     # манифест + 2 файла
        for cmd in calls:                          # шифрования нет — без keyfile
            self.assertNotIn("--keyfile", cmd)
            self.assertIn("PBS_PASSWORD_FILE=", cmd)
        log = self.read_log()
        self.assertIn("Снапшот PBS остаётся на сервере", log)
        self.assertIn("Временные файлы PBS удалены с ноды", log)
        self.assert_no_secrets(proc)
        self.assert_no_password_env(proc)
        self.assert_no_node_tempfiles()

    def test_pbs_encrypted_download_keyfile_everywhere(self):
        self.write_storage_cfg(
            "    encryption-key /etc/pve/priv/storage/pbs1.enc\n")
        self.make_key_file()
        self.write_config("pbs1")
        proc = self.run_script(["--download-existing"], stdin="2\n",
                               FAKE_PBS_STORAGE="1")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        downloaded = [p.name for p in self.dest.iterdir()]
        self.assertEqual(downloaded,
                         ["pbs-vm-105-2025-12-31T22-00-00Z.tar"])
        calls = self.client_calls()
        self.assertGreaterEqual(len(calls), 3)
        for cmd in calls:                          # --keyfile во ВСЕХ вызовах
            self.assertIn("--keyfile /etc/pve/priv/storage/pbs1.enc", cmd)
        log = self.read_log()
        self.assertIn("Хранилище «pbs1» настроено с шифрованием PBS", log)
        self.assertIn("Временные файлы PBS удалены с ноды", log)
        self.assert_no_secrets(proc)
        self.assert_no_password_env(proc)
        self.assert_no_node_tempfiles()

    def test_pbs_list_backups_still_works(self):
        self.write_config("pbs1")
        proc = self.run_script(["--list-backups"], FAKE_PBS_STORAGE="1")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("pbs1:backup/vm/105/2025-12-31T22:00:00Z", proc.stdout)
        self.assertIn("Хранилище типа PBS", proc.stdout)


# ---------------------------------------------------------------------------
# Проверка ключа шифрования: отказ ДО скачивания
# ---------------------------------------------------------------------------

class PbsKeyGuardTests(E2EBase):

    def run_expect_fail(self, message_part, **extra):
        self.write_config("pbs1")
        proc = self.run_script(["--download-existing"], stdin="1\n",
                               FAKE_PBS_STORAGE="1", **extra)
        self.assertEqual(proc.returncode, 1)
        log = self.read_log()
        self.assertIn("FAIL", log)
        self.assertIn(message_part, log)
        # скачивание не начиналось: ни одного вызова proxmox-backup-client
        self.assertEqual(self.client_calls(), [])
        self.assert_no_node_tempfiles()            # файл пароля не создавался
        self.assert_no_secrets(proc)
        return proc

    def test_key_missing(self):
        self.write_storage_cfg(
            "    encryption-key /etc/pve/priv/storage/pbs1.enc\n")
        proc = self.run_expect_fail("отсутствует")
        self.assertIn("/etc/pve/priv/storage/pbs1.enc", self.read_log())

    def test_key_not_regular_file(self):
        self.write_storage_cfg(
            "    encryption-key /etc/pve/priv/storage/pbs1.enc\n")
        priv = self.node / "priv" / "storage"
        priv.mkdir(parents=True, exist_ok=True)
        (priv / "pbs1.enc").mkdir()                # каталог вместо файла
        self.run_expect_fail("не является обычным файлом")

    def test_key_unreadable(self):
        self.write_storage_cfg(
            "    encryption-key /etc/pve/priv/storage/pbs1.enc\n")
        self.make_key_file()
        self.run_expect_fail("нет прав на чтение", FAKE_KEY_UNREADABLE="1")

    def test_key_empty(self):
        self.write_storage_cfg(
            "    encryption-key /etc/pve/priv/storage/pbs1.enc\n")
        self.make_key_file(content=b"")
        self.run_expect_fail("пуст")

    def test_no_encryption_configured_key_not_checked(self):
        # .enc-файл лежит, но encryption-key в storage.cfg нет: файл ключа
        # не проверяется и НЕ передаётся (наличие .enc ≠ шифрование)
        self.make_key_file()
        self.write_config("pbs1")
        proc = self.run_script(["--download-existing"], stdin="1\n",
                               FAKE_PBS_STORAGE="1")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(
            [c for c in self.client_calls() if "--keyfile" in c], [])


# ---------------------------------------------------------------------------
# Очистка временных файлов при ошибках операции PBS
# ---------------------------------------------------------------------------

class PbsCleanupTests(E2EBase):

    def setUp(self):
        super().setUp()
        self.write_config("pbs1")

    def test_scp_failure_cleans_tempfiles(self):
        proc = self.run_script(["--download-existing"], stdin="1\n",
                               FAKE_PBS_STORAGE="1", FAKE_SCP_FAIL="1")
        self.assertEqual(proc.returncode, 1)
        log = self.read_log()
        self.assertIn("scp завершился с кодом 1", log)
        self.assertIn("Временные файлы PBS удалены с ноды", log)
        self.assert_no_node_tempfiles()
        self.assert_no_secrets(proc)

    def test_restore_failure_cleans_tempfiles(self):
        proc = self.run_script(["--download-existing"], stdin="1\n",
                               FAKE_PBS_STORAGE="1", FAKE_PBS_RESTORE_FAIL="1")
        self.assertEqual(proc.returncode, 1)
        log = self.read_log()
        self.assertIn("не удалось получить манифест", log)
        # файл пароля уже был создан — и всё равно попал в очистку
        self.assertIn("Временные файлы PBS удалены с ноды", log)
        self.assert_no_node_tempfiles()
        self.assert_no_secrets(proc)

    def test_tar_failure_cleans_tempfiles(self):
        proc = self.run_script(["--download-existing"], stdin="1\n",
                               FAKE_PBS_STORAGE="1", FAKE_TAR_FAIL="1")
        self.assertEqual(proc.returncode, 1)
        log = self.read_log()
        self.assertIn("tar", log)
        self.assertIn("Временные файлы PBS удалены с ноды", log)
        self.assert_no_node_tempfiles()
        self.assert_no_secrets(proc)

    def test_rm_failure_warns_files_may_remain(self):
        proc = self.run_script(["--download-existing"], stdin="1\n",
                               FAKE_PBS_STORAGE="1", FAKE_RM_FAIL="1")
        # загрузка прошла, но очистку подтвердить не удалось
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        log = self.read_log()
        self.assertIn("могли остаться на узле Proxmox", log)
        self.assert_no_secrets(proc)


# ---------------------------------------------------------------------------
# §2.4 Отсутствующий столбец Available
# ---------------------------------------------------------------------------

class StorageDisplayTests(E2EBase):

    def test_missing_available_shows_unknown_not_zero(self):
        self.write_config("local")
        proc = self.run_script(["-i"], stdin="4\n\n\ny\n",
                               FAKE_PVESM_STATUS_NOAVAIL="1")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("свободное место: неизвестно", proc.stdout)
        self.assertNotIn("свободно 0", proc.stdout)
        log = self.read_log()
        self.assertIn("нет столбца Available", log)
        self.assert_no_secrets(proc)

    def test_no_header_fallback_warns(self):
        self.write_config("local")
        proc = self.run_script(["--list-backups"],
                               FAKE_PVESM_STATUS_MESSY="1")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("резервный разбор", self.read_log())


if __name__ == "__main__":
    unittest.main(verbosity=2)
