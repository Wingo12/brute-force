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

import hashlib
from colorama import init
from config import HASH_INFO

init(autoreset=True)

# Попытка импорта PyCryptodome для MD4
try:
    from Crypto.Hash import MD4 as _MD4
    _HAS_PYCRYPTODOME = True
except ImportError:
    _HAS_PYCRYPTODOME = False


def get_hasher(hash_type='md5'):
    """
    Возвращает функцию: password_bytes -> hexdigest.
    Бросает ValueError, если алгоритм недоступен.
    """
    if hash_type == 'md5':
        return lambda b: hashlib.md5(b).hexdigest()
    elif hash_type == 'md4':
        if 'md4' in hashlib.algorithms_available:
            return lambda b: hashlib.new('md4', b).hexdigest()
        if _HAS_PYCRYPTODOME:
            return lambda b: _MD4.new(b).hexdigest()
        raise ValueError("MD4 не поддерживается (ни OpenSSL, ни PyCryptodome)")
    elif hash_type == 'ripemd160':
        if 'ripemd160' not in hashlib.algorithms_available:
            raise ValueError("RIPEMD-160 не поддерживается в этой системе")
        return lambda b: hashlib.new('ripemd160', b).hexdigest()
    elif hash_type == 'sha1':
        return lambda b: hashlib.sha1(b).hexdigest()
    elif hash_type == 'sha224':
        return lambda b: hashlib.sha224(b).hexdigest()
    elif hash_type == 'sha256':
        return lambda b: hashlib.sha256(b).hexdigest()
    elif hash_type == 'sha384':
        return lambda b: hashlib.sha384(b).hexdigest()
    elif hash_type == 'sha512':
        return lambda b: hashlib.sha512(b).hexdigest()
    elif hash_type == 'sha3_224':
        return lambda b: hashlib.sha3_224(b).hexdigest()
    elif hash_type == 'sha3_256':
        return lambda b: hashlib.sha3_256(b).hexdigest()
    elif hash_type == 'sha3_384':
        return lambda b: hashlib.sha3_384(b).hexdigest()
    elif hash_type == 'sha3_512':
        return lambda b: hashlib.sha3_512(b).hexdigest()
    elif hash_type == 'blake2b_128':
        return lambda b: hashlib.blake2b(b, digest_size=16).hexdigest()
    elif hash_type == 'blake2s_128':
        return lambda b: hashlib.blake2s(b, digest_size=16).hexdigest()
    elif hash_type == 'blake2b':
        return lambda b: hashlib.blake2b(b).hexdigest()
    elif hash_type == 'blake2s':
        return lambda b: hashlib.blake2s(b).hexdigest()
    elif hash_type == 'shake128_32':
        return lambda b: hashlib.shake_128(b).hexdigest(16)
    elif hash_type == 'shake256_32':
        return lambda b: hashlib.shake_256(b).hexdigest(16)
    raise ValueError(f"Неизвестный алгоритм: {hash_type}")


def calculate_hash(password, hash_type='md5'):
    """Вычисление хеша пароля (совместимость со старым API)"""
    try:
        hasher = get_hasher(hash_type)
        return hasher(password.encode())
    except ValueError as e:
        return f"Ошибка: {e}"


def get_hash_info(hash_type):
    """Получение информации о хеш-алгоритме"""
    return HASH_INFO.get(hash_type, (hash_type.upper(), '?', 'Неизвестно'))


def validate_hash(target_hash, hash_type):
    """Проверяет длину и hex-формат хеша. Возвращает (ok, message)."""
    _, bits, _ = get_hash_info(hash_type)
    if bits == '?':
        return True, ""
    expected_len = bits // 4
    if len(target_hash) != expected_len:
        return False, f"Длина хеша {hash_type.upper()} должна быть {expected_len} символов (получено {len(target_hash)})"
    if not all(c in '0123456789abcdefABCDEF' for c in target_hash):
        return False, "Хеш должен содержать только hex-символы (0-9, a-f)"
    return True, ""


def check_hash_availability():
    return hashlib.algorithms_available
