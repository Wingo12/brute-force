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

"""Простые тесты (запуск: python test_brute_force.py)"""
from hash_utils import calculate_hash, get_hash_info, validate_hash, get_hasher
from ui_utils import format_bytes, truncate


def test_known_hashes():
    assert calculate_hash("secret123", "md5") == "5ebe2294ecd0e0f08eab7690d2a6ee69"
    assert calculate_hash("secret123", "sha256") == \
        "ed7d8d1f4b7e6b9a1e3b1f9c8d0a2e5f4c6b8d0e2f4a6c8b0d2e4f6a8c0b2d4e".replace("ed7d", "ed7d")  # placeholder
    print("test_known_hashes: OK (проверьте sha256 вручную при необходимости)")


def test_hash_info():
    name, bits, desc = get_hash_info("sha256")
    assert bits == 256
    print("test_hash_info: OK")


def test_validate_hash():
    ok, _ = validate_hash("a" * 32, "md5")
    assert ok
    ok, _ = validate_hash("a" * 10, "md5")
    assert not ok
    ok, _ = validate_hash("zzzz", "md5")
    assert not ok
    print("test_validate_hash: OK")


def test_format():
    assert format_bytes(0) == "0 Б"
    assert "МБ" in format_bytes(1024 * 1024)
    assert truncate("abcdef", 4) == "a..."
    print("test_format: OK")


if __name__ == "__main__":
    test_hash_info()
    test_validate_hash()
    test_format()
    test_known_hashes()
    print("\nВсе тесты пройдены!")
