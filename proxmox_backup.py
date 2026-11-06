#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""proxmox_backup.py — совместимая точка входа Proxmox Backup Script.

Привычный способ запуска сохранён (п. 4.3 ТЗ по реструктуризации):
`python3 proxmox_backup.py` и `./proxmox_backup.py` работают как раньше.
Реализация программы разобрана на модули (main.py, config.py, logger.py,
common.py, proxmox/, storage/, transfer/) — этот файл только делегирует
выполнение сценарию main() из main.py. Аргументы командной строки,
конфигурация и поведение не менялись.
"""

import sys

from main import main

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("Прервано пользователем.\n")
        sys.exit(130)
