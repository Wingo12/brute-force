#!/usr/bin/env python3
# GPLv3 License
# Author: Wingo12 (Wingo123)
"""
Проверяет наличие лицензионной шапки в .py файлах.
Если нет — добавляет блок GPLv3 + автор.
Использование: python add_license_headers.py [директория]
"""

import os
import sys

HEADER_MARKER = "GPLv3"
AUTHOR_MARKER = "Wingo12"

HEADER_TEMPLATE = """# GPLv3 License
# Author: Wingo12 (Wingo123)
"""

SKIP_FILES = {'add_license_headers.py', '__init__.py'}


def has_header(filepath: str) -> bool:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            head = ''.join(f.readline() for _ in range(10))
        return HEADER_MARKER in head and AUTHOR_MARKER in head
    except Exception:
        return False


def add_header(filepath: str) -> bool:
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"  [ОШИБКА] Не удалось прочитать: {e}")
        return False

    if HEADER_MARKER in content[:500] and AUTHOR_MARKER in content[:500]:
        return False

    lines = content.split('\n')
    insert_at = 0

    if lines and lines[0].startswith('#!'):
        insert_at = 1
        while insert_at < len(lines) and lines[insert_at].strip() == '':
            insert_at += 1

    new_lines = lines[:insert_at] + HEADER_TEMPLATE.split('\n') + lines[insert_at:]
    new_content = '\n'.join(new_lines)

    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        return True
    except Exception as e:
        print(f"  [ОШИБКА] Не удалось записать: {e}")
        return False


def main():
    target_dir = sys.argv[1] if len(sys.argv) > 1 else '.'

    if not os.path.isdir(target_dir):
        print(f"Директория не найдена: {target_dir}")
        sys.exit(1)

    print(f"Сканирую: {os.path.abspath(target_dir)}\n")

    added = skipped = errors = 0

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
        for filename in files:
            if not filename.endswith('.py'):
                continue
            if filename in SKIP_FILES:
                skipped += 1
                continue

            filepath = os.path.join(root, filename)
            rel = os.path.relpath(filepath, target_dir)

            if has_header(filepath):
                print(f"  [OK]    {rel}")
                skipped += 1
            else:
                if add_header(filepath):
                    print(f"  [ADDED] {rel}")
                    added += 1
                else:
                    print(f"  [FAIL]  {rel}")
                    errors += 1

    print(f"\nИтого: добавлено {added}, пропущено {skipped}, ошибок {errors}")


if __name__ == '__main__':
    main()
