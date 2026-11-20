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
import time
import gc
from concurrent.futures import ThreadPoolExecutor, as_completed

from colorama import Fore, Style, init
import config
from hash_utils import get_hasher, get_hash_info, validate_hash
from file_utils import find_pass_file, count_lines
from ui_utils import format_bytes, truncate, boxed, clear_progress_line
from wpa_utils import (
    parse_hc22000_line, parse_pcap_handshakes,
    verify_pmkid, verify_eapol_mic,
)

init(autoreset=True)

_process = None


def check_memory_usage():
    """Проверка использования памяти (кеширует psutil.Process)."""
    global _process
    if _process is None:
        try:
            import psutil
            _process = psutil.Process()
        except ImportError:
            return 0
        except Exception:
            return 0
    try:
        return _process.memory_info().rss
    except Exception:
        return 0


def iter_passwords(filepath):
    """Генератор паролей из файла"""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            pwd = line.strip()
            if pwd:
                yield pwd


def brute_force_password(target_hash=None, target_password=None, hash_type='md5'):
    """
    Брутфорс по хешу или точному паролю.
    """
    filepath = find_pass_file()
    if filepath is None:
        print(f"{Fore.RED}Файл pass.txt не найден")
        return None

    if target_hash:
        ok, msg = validate_hash(target_hash, hash_type)
        if not ok:
            print(f"{Fore.RED}[ОШИБКА] {msg}")
            return None

    try:
        hasher = get_hasher(hash_type)
    except ValueError as e:
        print(f"{Fore.RED}[ОШИБКА] {e}")
        return None

    hash_name, bits, desc = get_hash_info(hash_type)

    print(f"{Fore.CYAN}[INFO] Файл: {filepath}")
    print(f"{Fore.CYAN}[INFO] Алгоритм: {Fore.YELLOW}{hash_name} ({bits} бит)")
    print(f"{Fore.CYAN}[INFO] {desc}")
    print(f"{Fore.CYAN}[INFO] Лимит памяти: {Fore.YELLOW}{format_bytes(config.MEMORY_LIMIT_BYTES)}")
    print(f"{Fore.CYAN}[INFO] Режим: {'Задержка ' + str(config.DELAY_SECONDS) + 'с' if config.DELAY_ENABLED else 'Максимум'}")

    total_lines = None
    if config.SHOW_ETA:
        try:
            total_lines = count_lines(filepath)
            print(f"{Fore.CYAN}[INFO] Всего строк: {Fore.YELLOW}{total_lines:,}")
        except Exception:
            total_lines = None

    print(f"{Fore.CYAN}[INFO] Начинаю перебор...{Style.RESET_ALL}\n")

    start_time = time.time()
    attempts = 0
    last_update = time.time()
    found = None
    found_hash = None

    gc.collect()

    try:
        for password in iter_passwords(filepath):
            attempts += 1

            if attempts % config.MEMORY_CHECK_INTERVAL == 0:
                memory_usage = check_memory_usage()
                if memory_usage > config.MEMORY_LIMIT_BYTES and memory_usage > 0:
                    clear_progress_line()
                    print(f"{Fore.RED}[ПРЕДУПРЕЖДЕНИЕ] Превышен лимит памяти!{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}Использовано: {format_bytes(memory_usage)} / {format_bytes(config.MEMORY_LIMIT_BYTES)}")
                    gc.collect()
                    memory_usage = check_memory_usage()
                    if memory_usage > config.MEMORY_LIMIT_BYTES:
                        print(f"{Fore.RED}[ОШИБКА] Недостаточно памяти! Остановка...{Style.RESET_ALL}")
                        return None
                    print(f"{Fore.GREEN}Память очищена! Продолжаем...{Style.RESET_ALL}\n")

            current_time = time.time()
            if current_time - last_update > 0.5:
                elapsed = current_time - start_time
                speed = attempts / elapsed if elapsed > 0 else 0
                memory_usage = check_memory_usage()

                if config.MEMORY_LIMIT_BYTES > 0 and memory_usage > 0:
                    mem_percent = (memory_usage / config.MEMORY_LIMIT_BYTES) * 100
                    mem_color = Fore.GREEN if mem_percent < 70 else (Fore.YELLOW if mem_percent < 90 else Fore.RED)
                    mem_info = f"{mem_color}RAM: {format_bytes(memory_usage)} ({mem_percent:.0f}%){Style.RESET_ALL}"
                else:
                    mem_info = f"{Fore.CYAN}RAM: N/A{Style.RESET_ALL}"

                eta_str = ""
                if total_lines and speed > 0:
                    remaining = total_lines - attempts
                    eta_sec = remaining / speed
                    eta_str = f" | {Fore.CYAN}ETA: {int(eta_sec // 60)}м {int(eta_sec % 60)}с{Style.RESET_ALL}"

                preview = truncate(password, 25)

                clear_progress_line()
                print(f"\r{Fore.MAGENTA}Попыток: {attempts:,} | "
                      f"{Fore.GREEN}{speed:.0f} п/с | "
                      f"{mem_info}{eta_str} | "
                      f"{Fore.WHITE}{preview}",
                      end='', flush=True)

                last_update = current_time

            if target_hash:
                pwd_hash = hasher(password.encode())
                if pwd_hash.lower() == target_hash.lower():
                    found = password
                    found_hash = pwd_hash
                    break
            if target_password and password == target_password:
                found = password
                break
            if not target_hash and not target_password:
                if password == config.DEMO_TARGET_PASSWORD:
                    found = password
                    break

            if config.DELAY_ENABLED and attempts % config.BATCH_SIZE == 0:
                time.sleep(config.DELAY_SECONDS)

    except MemoryError:
        clear_progress_line()
        print(f"{Fore.RED}[ОШИБКА] Недостаточно памяти{Style.RESET_ALL}")
        return None
    except KeyboardInterrupt:
        clear_progress_line()
        elapsed = time.time() - start_time
        print(f"\n\n{Fore.YELLOW}[ПРЕРВАНО] Проверено {attempts:,} паролей за {elapsed:.1f}с")
        return None
    except Exception as e:
        clear_progress_line()
        print(f"\n\n{Fore.RED}[ОШИБКА] {str(e)}{Style.RESET_ALL}")
        return None

    clear_progress_line()
    elapsed = time.time() - start_time

    if found:
        lines = [f"{Fore.CYAN} Пароль: {Fore.YELLOW}{truncate(found, 50)}"]
        if target_hash:
            lines.append(f"{Fore.CYAN} Хеш: {Fore.YELLOW}{truncate(found_hash, 48)}")
        lines += [
            f"{Fore.CYAN} Попыток: {Fore.YELLOW}{attempts:,}",
            f"{Fore.CYAN} Время: {Fore.YELLOW}{elapsed:.2f} сек",
            f"{Fore.CYAN} Скорость: {Fore.YELLOW}{attempts / elapsed:.0f} п/с" if elapsed > 0 else "",
        ]
        print()
        boxed("ПАРОЛЬ НАЙДЕН!", lines, color=Fore.GREEN)
        return found
    else:
        lines = [
            f"{Fore.CYAN} Проверено: {Fore.YELLOW}{attempts:,}",
            f"{Fore.CYAN} Время: {Fore.YELLOW}{elapsed:.2f} сек",
            f"{Fore.CYAN} Скорость: {Fore.YELLOW}{attempts / elapsed:.0f} п/с" if elapsed > 0 else "",
        ]
        print()
        boxed("ПАРОЛЬ НЕ НАЙДЕН", lines, color=Fore.RED)
        print(f"{Fore.YELLOW}Подсказка: добавьте пароли в файл (пункт 5) или смените алгоритм")
        return None


# ============================================================
# Wi-Fi перебор (PMKID / EAPOL) с многопоточностью
# ============================================================

def _check_one_password_wifi(password: str, targets: list[dict]) -> tuple[str, dict] | None:
    """Проверяет один пароль по всем целям."""
    for target in targets:
        try:
            if target['type'] == 'PMKID':
                ok = verify_pmkid(
                    password, target['essid'],
                    target['mac_ap'], target['mac_sta'],
                    target['pmkid'],
                )
            else:
                ok = verify_eapol_mic(
                    password, target['essid'],
                    target['mac_ap'], target['mac_sta'],
                    target['nonce_ap'], target['nonce_sta'],
                    target['eapol'], target['mic'],
                )
        except Exception:
            continue
        if ok:
            return password, target
    return None


def brute_force_wifi(target_path: str, workers: int | None = None):
    """
    Перебор Wi-Fi паролей. Автоопределение: .hc22000 / .pcap / .pcapng
    """
    wordlist = find_pass_file()
    if not wordlist:
        print(f"{Fore.RED}Словарь pass.txt не найден")
        return None

    targets = []
    ext = os.path.splitext(target_path)[1].lower()

    if ext in ('.pcap', '.pcapng'):
        print(f"{Fore.CYAN}[INFO] Парсинг raw pcap: {target_path}")
        try:
            targets = parse_pcap_handshakes(target_path)
        except Exception as e:
            print(f"{Fore.RED}[ОШИБКА] {e}")
            return None
    else:
        print(f"{Fore.CYAN}[INFO] Парсинг hc22000: {target_path}")
        try:
            with open(target_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parsed = parse_hc22000_line(line)
                    if parsed:
                        targets.append(parsed)
        except FileNotFoundError:
            print(f"{Fore.RED}Файл {target_path} не найден")
            return None

    if not targets:
        print(f"{Fore.RED}Не найдено ни одной цели (PMKID или EAPOL)")
        return None

    for t in targets:
        ssid_disp = t['essid'].decode('utf-8', errors='ignore')
        print(f"{Fore.CYAN}[INFO] Цель [{t['type']}]: SSID='{ssid_disp}'")

    try:
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Fore.RED}Ошибка чтения словаря: {e}")
        return None

    total = len(passwords)
    actual_workers = workers or config.WIFI_WORKERS or os.cpu_count() or 1
    print(f"{Fore.CYAN}[INFO] Словарь: {total:,} паролей")
    print(f"{Fore.CYAN}[INFO] Потоков: {actual_workers}")
    print(f"{Fore.YELLOW}[ПРЕДУПРЕЖДЕНИЕ] PBKDF2 4096 итераций — CPU-bound\n")

    start = time.time()
    completed = 0
    found = None

    try:
        with ThreadPoolExecutor(max_workers=actual_workers) as pool:
            futures = {
                pool.submit(_check_one_password_wifi, pwd, targets): pwd
                for pwd in passwords
            }

            for future in as_completed(futures):
                completed += 1
                result = future.result()
                if result:
                    found_pwd, found_target = result
                    found = found_pwd
                    for f in futures:
                        f.cancel()
                    break

                if completed % 200 == 0 or completed == total:
                    elapsed = time.time() - start
                    speed = completed / elapsed if elapsed > 0 else 0
                    print(f"\r{Fore.MAGENTA}Проверено: {completed:,}/{total:,} | "
                          f"{Fore.GREEN}{speed:.0f} п/с", end='', flush=True)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[ПРЕРВАНО] {completed:,} проверено")
        return None

    elapsed = time.time() - start
    print()

    if found:
        ssid_disp = found_target['essid'].decode('utf-8', errors='ignore')
        print(f"{Fore.GREEN}[+] ПАРОЛЬ НАЙДЕН: {found}")
        print(f"{Fore.CYAN}    SSID: {ssid_disp}")
        print(f"{Fore.CYAN}    Тип: {found_target['type']}")
        print(f"{Fore.CYAN}    Время: {elapsed:.1f}с")
        return found

    print(f"{Fore.RED}Пароль не найден ({completed:,} проверено за {elapsed:.1f}с)")
    return None
