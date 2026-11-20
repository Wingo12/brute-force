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

# Настройки производительности
DELAY_ENABLED = True
DELAY_SECONDS = 0.1
BATCH_SIZE = 10

# Настройки памяти (в байтах)
MEMORY_LIMIT_MB = 512
MEMORY_LIMIT_BYTES = MEMORY_LIMIT_MB * 1024 * 1024
MEMORY_CHECK_INTERVAL = 10000

# Demo-режим
DEMO_TARGET_PASSWORD = "secret123"

# ETA в прогрессе (требует подсчёта строк)
SHOW_ETA = False

# Wi-Fi: число потоков (None = auto по CPU)
WIFI_WORKERS = None

# Информация о хеш-алгоритмах
HASH_INFO = {
    'md5': ('MD5', 128, 'Устаревший, есть коллизии'),
    'md4': ('MD4', 128, 'Устаревший, небезопасный'),
    'ripemd160': ('RIPEMD-160', 160, 'Европейский стандарт'),
    'sha1': ('SHA-1', 160, 'Устаревший, есть атаки'),
    'sha224': ('SHA-224', 224, 'Часть семейства SHA-2'),
    'sha256': ('SHA-256', 256, 'Рекомендуемый стандарт'),
    'sha384': ('SHA-384', 384, 'Часть семейства SHA-2'),
    'sha512': ('SHA-512', 512, 'Высокая безопасность'),
    'sha3_224': ('SHA3-224', 224, 'Новый стандарт SHA-3'),
    'sha3_256': ('SHA3-256', 256, 'Новый стандарт SHA-3'),
    'sha3_384': ('SHA3-384', 384, 'Новый стандарт SHA-3'),
    'sha3_512': ('SHA3-512', 512, 'Новый стандарт SHA-3'),
    'blake2b_128': ('BLAKE2b-128', 128, 'Современный, быстрый'),
    'blake2s_128': ('BLAKE2s-128', 128, 'Для 32-бит систем'),
    'blake2b': ('BLAKE2b', 512, 'Современный, быстрый'),
    'blake2s': ('BLAKE2s', 256, 'Для 32-бит систем'),
    'shake128_32': ('SHAKE128', 128, 'Расширяемый выход'),
    'shake256_32': ('SHAKE256', 256, 'Расширяемый выход')
}

HASH_GROUPS = {
    '128-bit (реальные)': [
        ('md5', 'MD5'),
        ('md4', 'MD4'),
        ('blake2b_128', 'BLAKE2b-128'),
        ('blake2s_128', 'BLAKE2s-128'),
        ('shake128_32', 'SHAKE128')
    ],
    '160-bit': [
        ('sha1', 'SHA-1'),
        ('ripemd160', 'RIPEMD-160')
    ],
    '224-bit': [
        ('sha224', 'SHA-224'),
        ('sha3_224', 'SHA3-224')
    ],
    '256-bit': [
        ('sha256', 'SHA-256'),
        ('sha3_256', 'SHA3-256'),
        ('blake2s', 'BLAKE2s')
    ],
    '384-bit': [
        ('sha384', 'SHA-384'),
        ('sha3_384', 'SHA3-384')
    ],
    '512-bit': [
        ('sha512', 'SHA-512'),
        ('sha3_512', 'SHA3-512'),
        ('blake2b', 'BLAKE2b'),
        ('shake256_32', 'SHAKE256')
    ]
}

ALGORITHMS_LIST = [
    ('1', 'md5', 'MD5 (128 бит)'),
    ('2', 'md4', 'MD4 (128 бит)'),
    ('3', 'blake2b_128', 'BLAKE2b-128 (128 бит)'),
    ('4', 'blake2s_128', 'BLAKE2s-128 (128 бит)'),
    ('5', 'shake128_32', 'SHAKE128 (128 бит)'),
    ('6', 'sha1', 'SHA-1 (160 бит)'),
    ('7', 'ripemd160', 'RIPEMD-160 (160 бит)'),
    ('8', 'sha256', 'SHA-256 (256 бит)'),
    ('9', 'sha3_256', 'SHA3-256 (256 бит)'),
    ('10', 'blake2b', 'BLAKE2b (512 бит)'),
    ('11', 'sha512', 'SHA-512 (512 бит)')
]


def update_memory_limit(mb):
    """Обновить лимит памяти с валидацией"""
    global MEMORY_LIMIT_MB, MEMORY_LIMIT_BYTES
    if not (0.03125 <= mb <= 8192):
        raise ValueError(f"Лимит памяти {mb} МБ вне диапазона 0.03125–8192")
    MEMORY_LIMIT_MB = mb
    MEMORY_LIMIT_BYTES = int(mb * 1024 * 1024)
