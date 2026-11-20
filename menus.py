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

from colorama import Fore, Style, init
import config
from config import update_memory_limit, HASH_GROUPS, ALGORITHMS_LIST
from hash_utils import calculate_hash, get_hash_info
from file_utils import add_passwords, view_file_preview
from brute_force import brute_force_password, brute_force_wifi
from ui_utils import format_bytes

init(autoreset=True)


def print_banner():
    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}║{Fore.YELLOW}              БРУТФОРС ПАРОЛЕЙ pass.txt                    {Fore.CYAN}║")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════╝")


def main_menu():
    while True:
        print(f"\n{Fore.CYAN}ГЛАВНОЕ МЕНЮ:")
        print(f"{Fore.WHITE}1. {Fore.YELLOW}Поиск demo пароля '{config.DEMO_TARGET_PASSWORD}'")
        print(f"{Fore.WHITE}2. {Fore.YELLOW}Поиск по хешу")
        print(f"{Fore.WHITE}3. {Fore.YELLOW}Поиск по точному паролю")
        print(f"{Fore.WHITE}4. {Fore.YELLOW}Создать хеши из пароля")
        print(f"{Fore.WHITE}5. {Fore.YELLOW}Добавить пароли в файл")
        print(f"{Fore.WHITE}6. {Fore.YELLOW}Просмотреть файл")
        print(f"{Fore.WHITE}7. {Fore.YELLOW}Информация об алгоритмах")
        print(f"{Fore.WHITE}8. {Fore.YELLOW}Настройки производительности")
        print(f"{Fore.WHITE}9. {Fore.YELLOW}Поиск по Wi-Fi (.hc22000 / .pcap / .pcapng)")
        print(f"{Fore.WHITE}0. {Fore.YELLOW}Выйти")

        try:
            choice = input(f"\n{Fore.CYAN}Выбор: {Fore.WHITE}").strip()
        except EOFError:
            print(f"\n{Fore.GREEN}До свидания!")
            break

        if choice == '1':
            brute_force_password()
        elif choice == '2':
            hash_search_menu()
        elif choice == '3':
            try:
                pwd = input(f"{Fore.CYAN}Введите пароль: {Fore.WHITE}").strip()
            except EOFError:
                continue
            if pwd:
                brute_force_password(target_password=pwd)
        elif choice == '4':
            create_hash_menu()
        elif choice == '5':
            add_passwords()
        elif choice == '6':
            view_file_preview()
        elif choice == '7':
            info_menu()
        elif choice == '8':
            settings_menu()
        elif choice == '9':
            try:
                path = input(f"{Fore.CYAN}Путь к файлу (.hc22000/.pcap/.pcapng): {Fore.WHITE}").strip()
            except EOFError:
                continue
            if path:
                brute_force_wifi(path)
        elif choice == '0':
            print(f"{Fore.GREEN}До свидания!")
            break


def hash_search_menu():
    print(f"\n{Fore.CYAN}Доступные алгоритмы:")
    for num, code, desc in ALGORITHMS_LIST:
        print(f"{Fore.WHITE}{num}. {Fore.YELLOW}{desc}")

    try:
        choice = input(f"\n{Fore.CYAN}Выберите номер: {Fore.WHITE}").strip()
    except EOFError:
        return

    algo_dict = {num: code for num, code, _ in ALGORITHMS_LIST}
    if choice not in algo_dict:
        print(f"{Fore.RED}Неверный выбор")
        return

    hash_type = algo_dict[choice]
    hash_name, _, _ = get_hash_info(hash_type)

    try:
        target = input(f"{Fore.CYAN}Введите {hash_name} хеш: {Fore.WHITE}").strip()
    except EOFError:
        return

    if target:
        brute_force_password(target_hash=target, hash_type=hash_type)


def create_hash_menu():
    try:
        pwd = input(f"{Fore.CYAN}Введите пароль: {Fore.WHITE}").strip()
    except EOFError:
        return
    if not pwd:
        return

    print(f"\n{Fore.GREEN}Хеши для '{pwd}':\n")

    for group_name, algorithms in HASH_GROUPS.items():
        print(f"{Fore.CYAN}=== {group_name} ===")
        for hash_type, display_name in algorithms:
            hash_val = calculate_hash(pwd, hash_type)
            if not hash_val.startswith('Ошибка'):
                print(f"{Fore.YELLOW}{display_name}:")
                print(f"{Fore.WHITE}{hash_val}\n")

    try:
        save = input(f"{Fore.CYAN}Сохранить в файл? (y/n): ").lower()
    except EOFError:
        return

    if save == 'y':
        try:
            fname = input(f"{Fore.CYAN}Имя файла: ").strip() or 'hashes.txt'
        except EOFError:
            fname = 'hashes.txt'
        try:
            with open(fname, 'w', encoding='utf-8') as f:
                f.write(f"Пароль: {pwd}\n\n")
                for group_name, algorithms in HASH_GROUPS.items():
                    f.write(f"\n{group_name}:\n")
                    for hash_type, display_name in algorithms:
                        f.write(f"{display_name}: {calculate_hash(pwd, hash_type)}\n")
            print(f"{Fore.GREEN}Сохранено в {fname}")
        except Exception as e:
            print(f"{Fore.RED}Ошибка сохранения: {e}")


def info_menu():
    print(f"\n{Fore.CYAN}ИНФОРМАЦИЯ ОБ АЛГОРИТМАХ:\n")
    for name, bits, desc in [
        ('MD5', 128, 'Устаревший, не рекомендуется'),
        ('MD4', 128, 'Устаревший, небезопасный'),
        ('BLAKE2b-128', 128, 'Современный, быстрый'),
        ('SHAKE128', 128, 'Расширяемый выход'),
        ('SHA-1', 160, 'Устаревший, есть атаки'),
        ('RIPEMD-160', 160, 'Европейский стандарт'),
        ('SHA-256', 256, 'Рекомендуемый стандарт'),
        ('SHA3-256', 256, 'Новый стандарт SHA-3'),
        ('BLAKE2b', 512, 'Современный, быстрее SHA'),
        ('SHA-512', 512, 'Высокая безопасность')
    ]:
        print(f"{Fore.YELLOW}{name} ({bits} бит):")
        print(f"{Fore.WHITE}  {desc}\n")


def settings_menu():
    while True:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║{Fore.YELLOW}                  НАСТРОЙКИ ПРОИЗВОДИТЕЛЬНОСТИ               {Fore.CYAN}║")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

        print(f"{Fore.WHITE}1. {Fore.YELLOW}Задержка: {Fore.CYAN}{'ВКЛ' if config.DELAY_ENABLED else 'ВЫКЛ'}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}2. {Fore.YELLOW}Время задержки: {Fore.CYAN}{config.DELAY_SECONDS} сек{Style.RESET_ALL}")
        print(f"{Fore.WHITE}3. {Fore.YELLOW}Размер пакета: {Fore.CYAN}{config.BATCH_SIZE} попыток{Style.RESET_ALL}")
        print(f"{Fore.WHITE}4. {Fore.YELLOW}Лимит памяти: {Fore.CYAN}{config.MEMORY_LIMIT_MB} МБ ({format_bytes(config.MEMORY_LIMIT_BYTES)}){Style.RESET_ALL}")
        print(f"{Fore.WHITE}5. {Fore.YELLOW}Показывать ETA: {Fore.CYAN}{'ВКЛ' if config.SHOW_ETA else 'ВЫКЛ'}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}6. {Fore.YELLOW}Потоков Wi-Fi: {Fore.CYAN}{config.WIFI_WORKERS or 'auto'}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}7. {Fore.YELLOW}Назад{Style.RESET_ALL}")

        try:
            choice = input(f"\n{Fore.CYAN}Выбор: {Fore.WHITE}").strip()
        except EOFError:
            break

        if choice == '1':
            config.DELAY_ENABLED = not config.DELAY_ENABLED
            print(f"{Fore.GREEN}Задержка {'включена' if config.DELAY_ENABLED else 'выключена'}")
        elif choice == '2':
            try:
                new = float(input(f"{Fore.CYAN}Введите время задержки (0.001-5.0): {Fore.WHITE}"))
                if 0.001 <= new <= 5.0:
                    config.DELAY_SECONDS = new
                    print(f"{Fore.GREEN}Задержка установлена: {new} сек")
                else:
                    print(f"{Fore.RED}Введите значение от 0.001 до 5.0")
            except (ValueError, EOFError):
                print(f"{Fore.RED}Ошибка ввода")
        elif choice == '3':
            try:
                new = int(input(f"{Fore.CYAN}Введите размер пакета (1-1000): {Fore.WHITE}"))
                if 1 <= new <= 1000:
                    config.BATCH_SIZE = new
                    print(f"{Fore.GREEN}Размер пакета установлен: {new}")
                else:
                    print(f"{Fore.RED}Введите значение от 1 до 1000")
            except (ValueError, EOFError):
                print(f"{Fore.RED}Ошибка ввода")
        elif choice == '4':
            memory_settings_menu()
        elif choice == '5':
            config.SHOW_ETA = not config.SHOW_ETA
            print(f"{Fore.GREEN}ETA {'включён' if config.SHOW_ETA else 'выключен'}")
        elif choice == '6':
            try:
                val = input(f"{Fore.CYAN}Потоков (1-64, 0=auto): {Fore.WHITE}").strip()
                n = int(val)
                if n == 0:
                    config.WIFI_WORKERS = None
                    print(f"{Fore.GREEN}Потоков: auto")
                elif 1 <= n <= 64:
                    config.WIFI_WORKERS = n
                    print(f"{Fore.GREEN}Потоков: {n}")
                else:
                    print(f"{Fore.RED}Введите 0-64")
            except (ValueError, EOFError):
                print(f"{Fore.RED}Ошибка ввода")
        elif choice == '7':
            break
        else:
            print(f"{Fore.RED}Неверный выбор")


def memory_settings_menu():
    print(f"\n{Fore.CYAN}НАСТРОЙКИ ПАМЯТИ:")
    print(f"{Fore.WHITE}Текущий лимит: {Fore.YELLOW}{config.MEMORY_LIMIT_MB} МБ ({format_bytes(config.MEMORY_LIMIT_BYTES)})")
    print(f"{Fore.WHITE}1. {Fore.YELLOW}32 КБ{Style.RESET_ALL}")
    print(f"{Fore.WHITE}2. {Fore.YELLOW}64 МБ{Style.RESET_ALL}")
    print(f"{Fore.WHITE}3. {Fore.YELLOW}128 МБ{Style.RESET_ALL}")
    print(f"{Fore.WHITE}4. {Fore.YELLOW}256 МБ{Style.RESET_ALL}")
    print(f"{Fore.WHITE}5. {Fore.YELLOW}512 МБ (стандарт){Style.RESET_ALL}")
    print(f"{Fore.WHITE}6. {Fore.YELLOW}1 ГБ{Style.RESET_ALL}")
    print(f"{Fore.WHITE}7. {Fore.YELLOW}2 ГБ{Style.RESET_ALL}")
    print(f"{Fore.WHITE}8. {Fore.YELLOW}4 ГБ{Style.RESET_ALL}")
    print(f"{Fore.WHITE}9. {Fore.YELLOW}8 ГБ{Style.RESET_ALL}")
    print(f"{Fore.WHITE}0. {Fore.YELLOW}Своё значение{Style.RESET_ALL}")
    print(f"{Fore.WHITE}q. {Fore.YELLOW}Назад{Style.RESET_ALL}")

    try:
        choice = input(f"\n{Fore.CYAN}Выбор: {Fore.WHITE}").strip()
    except EOFError:
        return

    presets = {
        '1': (0.03125, "32 КБ"),
        '2': (64, "64 МБ"),
        '3': (128, "128 МБ"),
        '4': (256, "256 МБ"),
        '5': (512, "512 МБ"),
        '6': (1024, "1 ГБ"),
        '7': (2048, "2 ГБ"),
        '8': (4096, "4 ГБ"),
        '9': (8192, "8 ГБ"),
    }

    if choice in presets:
        mb, label = presets[choice]
        try:
            update_memory_limit(mb)
            print(f"{Fore.GREEN}Лимит памяти: {label}")
        except ValueError as e:
            print(f"{Fore.RED}{e}")
    elif choice == '0':
        try:
            custom = float(input(f"{Fore.CYAN}Введите лимит в МБ (0.03125-8192): {Fore.WHITE}"))
            update_memory_limit(custom)
            print(f"{Fore.GREEN}Лимит памяти: {custom} МБ")
        except (ValueError, EOFError) as e:
            print(f"{Fore.RED}Ошибка: {e}")
    elif choice == 'q':
        return
    else:
        print(f"{Fore.RED}Неверный выбор")
