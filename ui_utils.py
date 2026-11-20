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

init(autoreset=True)


def format_bytes(bytes_val):
    """Форматирование байтов в читаемый вид"""
    if bytes_val == 0:
        return "0 Б"
    for unit in ['Б', 'КБ', 'МБ', 'ГБ']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} ТБ"


def truncate(text, max_len):
    """Обрезка строки с многоточием"""
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def boxed(title, lines, color=Fore.CYAN, width=60):
    """Рисует рамку с заголовком и строками"""
    print(f"{color}╔{'═' * width}╗")
    print(f"{color}║{Fore.YELLOW}{title:^{width}}{color}║")
    print(f"{color}╠{'═' * width}╣")
    for line in lines:
        print(f"{color}║ {line:<{width - 2}} {color}║")
    print(f"{color}╚{'═' * width}╝{Style.RESET_ALL}")


def clear_progress_line():
    """Очищает текущую строку прогресса"""
    print("\r\033[K", end='', flush=True)
