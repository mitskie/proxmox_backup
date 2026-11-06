# -*- coding: utf-8 -*-
"""SSH/SCP-взаимодействие с нодой Proxmox.

Перенесено из proxmox_backup.py v5 без изменений: способ подключения
(внешние ssh/scp через псевдо-терминал pty), обработка prompts пароля
и host key, выполнение удалённых команд и копирование файлов сохранены.

Пароли и ключи в командах не передаются: пароль SSH отправляется
в псевдо-терминал только по запросу ssh и не попадает в DEBUG-лог
команд (логируется сама команда, а не ввод).
"""

import fcntl
import logging
import os
import pty
import re
import select
import shlex
import signal
import sys
import termios
import time

from common import AuthError, RemoteCommandError

LOG = logging.getLogger("pve-backup")

# --- распознавание prompts ssh в псевдо-терминале ---------------------------
PROMPT_RE = re.compile(rb"password\s*:\s*$", re.IGNORECASE)
HOSTKEY_RE = re.compile(rb"continue connecting[^\r\n]*\?\s*$", re.IGNORECASE)
READ_CHUNK = 65536
PROMPT_WINDOW = 4096


def _spawn_pty(cmd):
    """Запускает команду с управляющим псевдо-терминалом (для ввода пароля).

    Возвращает (pid, master_fd). Эхо терминала отключено, чтобы пароль
    не попадал в вывод.
    """
    master_fd, slave_fd = pty.openpty()
    attrs = termios.tcgetattr(slave_fd)
    attrs[3] &= ~termios.ECHO                      # lflag: не отображать ввод
    termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
    pid = os.fork()
    if pid == 0:                                   # дочерний процесс
        try:
            os.close(master_fd)
            os.setsid()                            # новая сессия
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)   # управляющий tty
            os.dup2(slave_fd, 0)
            os.dup2(slave_fd, 1)
            os.dup2(slave_fd, 2)
            if slave_fd > 2:
                os.close(slave_fd)
            os.execvp(cmd[0], cmd)
        except BaseException:
            pass
        os._exit(127)
    os.close(slave_fd)
    return pid, master_fd


def _wait_exit(pid):
    """Забирает статус завершённого потомка -> код возврата."""
    try:
        _, status = os.waitpid(pid, 0)
    except ChildProcessError:
        return -1
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    return -1


def _kill_child(pid):
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass


def run_session(cmd, password=None, timeout=0, passthrough=False):
    """Выполняет локальную команду (ssh/scp) через pty.

    Отвечает на запрос пароля и подтверждение host key. Возвращает
    (код_возврата, весь_вывод_строкой). timeout — лимит тишины в секундах
    (0 — без ограничения).
    """
    pid, master_fd = _spawn_pty(cmd)
    output = bytearray()
    post_auth = bytearray()          # данные после отправки пароля
    sent_password = False
    sent_yesno = False
    sent_at = 0                      # граница вывода «до/после» пароля
    last_data = time.monotonic()
    try:
        while True:
            wait = timeout if timeout and timeout > 0 else None
            ready, _, _ = select.select([master_fd], [], [], wait)
            if not ready:
                _kill_child(pid)
                raise RemoteCommandError(
                    f"таймаут бездействия {timeout} c: {shlex.join(cmd)}")
            try:
                chunk = os.read(master_fd, READ_CHUNK)
            except OSError:      # EIO: дочерний процесс закрыл tty
                break
            if not chunk:
                break
            last_data = time.monotonic()
            output += chunk
            if passthrough:
                try:
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()
                except OSError:
                    pass
            if password:
                window = bytes(output[-PROMPT_WINDOW:])
                if not sent_password:
                    if PROMPT_RE.search(window):
                        LOG.debug("SSH: запрошен пароль — отправляю")
                        sent_at = len(output)      # всё до пароля — служебный вывод ssh
                        os.write(master_fd, (password + "\n").encode())
                        sent_password = True
                    elif not sent_yesno and HOSTKEY_RE.search(window):
                        os.write(master_fd, b"yes\n")
                        sent_yesno = True
                else:
                    post_auth += chunk
                    if PROMPT_RE.search(bytes(post_auth[-512:])):
                        raise AuthError(
                            "SSH запросил пароль повторно — по-видимому, пароль неверён")
    except BaseException:
        _kill_child(pid)
        raise
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass
    rc = _wait_exit(pid)
    if sent_password:
        # отрезаем премаутентификационный мусор (промпт пароля, баннеры),
        # чтобы он не ломал разбор вывода команд
        output = output[sent_at:]
    text = output.decode("utf-8", errors="replace").replace("\r\n", "\n")
    return rc, text


# ----------------------------------------------------------------------------
# SSH / SCP
# ----------------------------------------------------------------------------

def _base_options(cfg, password):
    options = ["-o", "ConnectTimeout=10",
               "-o", "StrictHostKeyChecking=accept-new"]
    if not password:
        options += ["-o", "BatchMode=yes"]     # вход только по ключу
    key_file = cfg["proxmox"].get("key_file")
    if key_file:
        options += ["-i", os.path.expanduser(str(key_file))]
    return options


def _ssh_cmd(cfg, remote_cmd, password):
    proxmox = cfg["proxmox"]
    return (["ssh", "-p", str(proxmox["port"])]
            + _base_options(cfg, password)
            + [f"{proxmox['user']}@{proxmox['host']}", remote_cmd])


def _scp_cmd(cfg, remote_path, local_path, password):
    proxmox = cfg["proxmox"]
    cmd = ["scp", "-P", str(proxmox["port"])] + _base_options(cfg, password)
    if not sys.stdout.isatty():
        cmd.append("-q")                       # без прогресса в cron
    cmd += [f"{proxmox['user']}@{proxmox['host']}:{remote_path}", str(local_path)]
    return cmd


def _session_run(cmd, cfg, password, passthrough):
    timeout = int(cfg["proxmox"].get("ssh_timeout", 0) or 0)
    return run_session(cmd, password=password, timeout=timeout,
                       passthrough=passthrough)


def ssh_run(cfg, remote_cmd, check=True, passthrough=False):
    """Выполняет команду на ноде. Возвращает (код, вывод)."""
    password = cfg["proxmox"].get("_password")
    cmd = _ssh_cmd(cfg, remote_cmd, password)
    LOG.debug("SSH: %s", shlex.join(cmd))
    rc, out = _session_run(cmd, cfg, password, passthrough)
    if check and rc != 0:
        detail = out.strip()[-2000:]
        raise RemoteCommandError(
            f"ошибка выполнения на ноде (код {rc}): {remote_cmd}\n{detail}")
    return rc, out


def scp_pull(cfg, remote_path, local_path):
    """Копирует файл с ноды (вывод/прогресс идут в консоль)."""
    password = cfg["proxmox"].get("_password")
    cmd = _scp_cmd(cfg, remote_path, local_path, password)
    LOG.debug("SCP: %s", shlex.join(cmd))
    return _session_run(cmd, cfg, password, passthrough=True)
