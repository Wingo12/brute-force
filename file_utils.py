#!/usr/bin/env python3

# =============================================================================
#  Brute Force Password Tool
# =============================================================================
#  License : GNU General Public License v3.0 (GPLv3)
#  Author  : Wingo12 (Wingo123)
#  Project : https://github.com/Wingo12/brute-force
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.
# =============================================================================

import os
from colorama import Fore, Style, init
from config import DEMO_TARGET_PASSWORD

init(autoreset=True)

_PASS_FILE_CACHE = None


def find_pass_file(filename='pass.txt', use_cache=True):
    """Ищет файл в текущей и родительской директории."""
    global _PASS_FILE_CACHE
    if use_cache and _PASS_FILE_CACHE is not None:
        if os.path.exists(_PASS_FILE_CACHE):
            return _PASS_FILE_CACHE
        _PASS_FILE_CACHE = None

    if os.path.exists(filename):
        _PASS_FILE_CACHE = filename
        return filename
    parent_path = os.path.join('..', filename)
    if os.path.exists(parent_path):
        _PASS_FILE_CACHE = parent_path
        return parent_path
    return None


def get_file_size_mb(filename='pass.txt'):
    filepath = find_pass_file(filename)
    if filepath:
        return os.path.getsize(filepath) / (1024 * 1024)
    return 0


def count_lines(filepath):
    """Считает строки в файле (бинарный проход)."""
    with open(filepath, 'rb') as f:
        return sum(1 for _ in f)


def create_password_file():
    print(f"\n{Fore.CYAN}СОЗДАНИЕ ФАЙЛА С ПАРОЛЯМИ")
    print(f"{Fore.WHITE}Введите пароли (по одному). Пустая строка - выход.\n")

    passwords = []
    count = 1

    try:
        while True:
            pwd = input(f"{Fore.GREEN}Пароль #{count}: {Fore.WHITE}").strip().replace('\r', '')
            if not pwd:
                break
            passwords.append(pwd)
            print(f"{Fore.CYAN}  → Добавлен #{count}")
            count += 1
    except EOFError:
        print(f"\n{Fore.YELLOW}Ввод завершён")

    if passwords:
        try:
            with open('pass.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(passwords))
            print(f"\n{Fore.GREEN}Сохранено {len(passwords)} паролей в pass.txt")
            find_pass_file(use_cache=False)
            return True
        except Exception as e:
            print(f"{Fore.RED}Ошибка сохранения: {e}")
            return False
    return False


def create_demo_file():
    demo = ["123456", "password", "qwerty", "admin", "letmein",
            "welcome", "monkey", "dragon", DEMO_TARGET_PASSWORD, "master"]
    try:
        with open('pass.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(demo))
        find_pass_file(use_cache=False)
        print(f"{Fore.GREEN}Демо-файл создан с {len(demo)} паролями")
        print(f"{Fore.YELLOW}Целевой пароль: {DEMO_TARGET_PASSWORD}")
        return True
    except Exception as e:
        print(f"{Fore.RED}Ошибка: {e}")
        return False


def add_passwords():
    filepath = find_pass_file()
    if filepath is None:
        print(f"{Fore.RED}Файл pass.txt не найден")
        return False

    existing = set()
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            existing = set(line.strip() for line in f if line.strip())
    except Exception:
        pass

    print(f"{Fore.WHITE}В файле {len(existing)} паролей")
    print(f"{Fore.WHITE}Введите новые пароли (пустая строка - выход)\n")

    new_passwords = []
    count = 1

    try:
        while True:
            pwd = input(f"{Fore.GREEN}Новый #{count}: {Fore.WHITE}").strip().replace('\r', '')
            if not pwd:
                break
            if pwd in existing:
                print(f"{Fore.YELLOW}  → Уже есть")
            else:
                new_passwords.append(pwd)
                existing.add(pwd)
                print(f"{Fore.CYAN}  → Добавлен")
                count += 1
    except EOFError:
        print(f"\n{Fore.YELLOW}Ввод завершён")

    if new_passwords:
        try:
            with open(filepath, 'a', encoding='utf-8') as f:
                f.write('\n' + '\n'.join(new_passwords))
            print(f"{Fore.GREEN}Добавлено {len(new_passwords)} паролей")
            return True
        except Exception as e:
            print(f"{Fore.RED}Ошибка: {e}")
            return False
    return False


def view_file_preview(lines=20):
    filepath = find_pass_file()
    if filepath is None:
        print(f"{Fore.RED}Файл pass.txt не найден")
        return

    size_mb = get_file_size_mb()
    print(f"{Fore.CYAN}Файл: {filepath} ({size_mb:.1f} МБ)")

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            print(f"\n{Fore.CYAN}Первые {lines} строк:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}{'-' * 50}")
            for i in range(lines):
                line = f.readline()
                if not line:
                    break
                pwd = line.strip()
                display = pwd if len(pwd) <= 50 else pwd[:47] + "..."
                print(f"{Fore.YELLOW}{i + 1:3}.{Fore.WHITE} {display}")
            print(f"{Fore.WHITE}{'-' * 50}")

            f.seek(0, 2)
            file_size = f.tell()
            print(f"{Fore.CYAN}Размер файла: {file_size:,} байт ({size_mb:.2f} МБ)")
    except Exception as e:
        print(f"{Fore.RED}Ошибка: {e}")
