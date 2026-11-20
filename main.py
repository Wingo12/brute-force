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
import sys
from colorama import Fore, init
from menus import print_banner, main_menu
from file_utils import create_password_file, create_demo_file, find_pass_file

init(autoreset=True)


def startup():
    print_banner()
    found_file = find_pass_file()

    if found_file is None:
        print(f"{Fore.YELLOW}Файл pass.txt не найден в текущей или родительской директории.\n")
        print(f"{Fore.WHITE}1. {Fore.YELLOW}Создать файл в текущей папке")
        print(f"{Fore.WHITE}2. {Fore.YELLOW}Создать демо-файл в текущей папке")
        print(f"{Fore.WHITE}3. {Fore.YELLOW}Выход")

        try:
            choice = input(f"\n{Fore.CYAN}Выбор: ").strip()
        except EOFError:
            return False

        if choice == '1':
            return create_password_file()
        elif choice == '2':
            return create_demo_file()
        else:
            return False
    else:
        print(f"{Fore.GREEN}Файл pass.txt найден: {found_file}")
        return True


if __name__ == "__main__":
    try:
        if startup():
            main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Программа прервана")
    except Exception as e:
        print(f"\n{Fore.RED}Ошибка: {e}")
