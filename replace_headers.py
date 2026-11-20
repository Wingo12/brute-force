#!/usr/bin/env python3
"""
replace_headers.py — заменяет старые короткие лицензионные шапки на полные.
Удаляет блоки вида:
    # GPLv3 License
    # Author: Wingo12 (Wingo123)
и вставляет красивую полную шапку.

Использование: python replace_headers.py [директория]
"""

import os
import re
import sys

NEW_HEADER = """# =============================================================================
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
"""

SKIP_FILES = {'replace_headers.py', 'add_license_headers.py', '__init__.py'}

# Паттерн старой короткой шапки (2 строки)
OLD_HEADER_RE = re.compile(
    r'^#\s*GPLv3 License\s*\n#\s*Author:\s*Wingo12.*\n',
    re.MULTILINE
)

# Паттерн любой уже новой шапки (по маркеру)
NEW_HEADER_MARKER = 'Brute Force Password Tool'


def has_new_header(content: str) -> bool:
    return NEW_HEADER_MARKER in content[:1000]


def replace_header(filepath: str) -> str:
    """Возвращает статус: 'replaced', 'added', 'skipped', 'error'."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"  [ERROR] read: {e}")
        return 'error'

    # Если уже новая шапка — пропускаем
    if has_new_header(content):
        return 'skipped'

    # Удаляем старую короткую шапку (если есть)
    content_clean = OLD_HEADER_RE.sub('', content, count=1)

    # Определяем позицию вставки: после shebang (если есть)
    lines = content_clean.split('\n')
    insert_at = 0
    if lines and lines[0].startswith('#!'):
        insert_at = 1
        while insert_at < len(lines) and lines[insert_at].strip() == '':
            insert_at += 1

    # Собираем новый контент
    new_lines = lines[:insert_at] + NEW_HEADER.rstrip('\n').split('\n') + [''] + lines[insert_at:]
    new_content = '\n'.join(new_lines)

    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        return 'replaced' if content != content_clean else 'added'
    except Exception as e:
        print(f"  [ERROR] write: {e}")
        return 'error'


def main():
    target_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
    if not os.path.isdir(target_dir):
        print(f"Directory not found: {target_dir}")
        sys.exit(1)

    print(f"Scanning: {os.path.abspath(target_dir)}\n")
    stats = {'replaced': 0, 'added': 0, 'skipped': 0, 'error': 0}

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
        for filename in sorted(files):
            if not filename.endswith('.py'):
                continue
            if filename in SKIP_FILES:
                continue
            filepath = os.path.join(root, filename)
            rel = os.path.relpath(filepath, target_dir)
            status = replace_header(filepath)
            stats[status] += 1
            print(f"  [{status.upper():8}] {rel}")

    print(f"\nResult: replaced={stats['replaced']} added={stats['added']} "
          f"skipped={stats['skipped']} errors={stats['error']}")


if __name__ == '__main__':
    main()
