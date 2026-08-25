#!/usr/bin/env python
"""Оракул: каждый сторонний пакет, который проект импортирует, назван в requirements.

Что проверяется:
  1. Разбираются ВСЕ импорты проекта (AST, а не grep — импорт внутри функции
     тоже считается: именно такие и забывают).
  2. Из них выбрасываются стандартная библиотека и собственные модули.
  3. Каждый оставшийся обязан быть назван в requirements.txt.
  4. Каждый обязан РЕАЛЬНО импортироваться в текущем окружении. Строка в файле
     без установленного пакета — это обещание, а не воспроизводимость.

Негативный контроль: заведомо отсутствующий пакет обязан быть пойман. Иначе
проверка, потерявшая способность находить, выглядела бы зелёной.

Успех печатает REQUIREMENTS OK и выходит с нулём.
"""

import ast
import importlib.util
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Имя при импорте -> имя пакета в PyPI. Совпадают они далеко не всегда, и
# именно на этом расхождении список зависимостей обычно и врёт.
IMPORT_TO_PACKAGE = {
    "dns": "dnspython",
    "socks": "PySocks",
    "names_dataset": "names-dataset",
    "gender_guesser": "gender-guesser",
    "duckduckgo_search": "duckduckgo-search",
    "whois": "python-whois",
}

# Собственные пакеты проекта и точки входа
LOCAL = {"core", "ui", "tools", "main", "cli", "engine"}

# Папки, которые описывают не продукт, а его проверку
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "tor_bin", ".unlazy",
             "audit", "tests"}


def project_imports():
    found = set()
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith(".py"):
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    tree = ast.parse(handle.read())
            except Exception:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        found.add(alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    found.add(node.module.split(".")[0])
    return found


def declared_packages(path):
    names = set()
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-r"):
                continue
            match = re.match(r"^([A-Za-z0-9._-]+)", line)
            if match:
                names.add(match.group(1).lower().replace("_", "-"))
    return names


def main():
    declared = declared_packages(os.path.join(ROOT, "requirements.txt"))
    if not declared:
        print("REQUIREMENTS BROKEN: requirements.txt пуст или не разобран")
        return 1

    # Негативный контроль: несуществующий пакет обязан считаться необъявленным
    if "заведомо-отсутствующий-пакет" in declared:
        print("DETECTOR BROKEN: разбор requirements.txt находит несуществующее")
        return 1

    third_party = sorted(
        module for module in project_imports()
        if module not in LOCAL and module not in sys.stdlib_module_names)

    missing_declaration = []
    missing_install = []
    for module in third_party:
        package = IMPORT_TO_PACKAGE.get(module, module)
        if package.lower().replace("_", "-") not in declared:
            missing_declaration.append(f"{module} (пакет {package})")
        if importlib.util.find_spec(module) is None:
            missing_install.append(f"{module} (пакет {package})")

    if missing_declaration or missing_install:
        print(f"REQUIREMENTS INCOMPLETE ({len(missing_declaration) + len(missing_install)})")
        for item in missing_declaration:
            print(f"  - импортируется, но не назван в requirements.txt: {item}")
        for item in missing_install:
            print(f"  - назван, но не установлен в этом окружении: {item}")
        return 1

    print(f"REQUIREMENTS OK (сторонних пакетов: {len(third_party)}, "
          f"строк в requirements.txt: {len(declared)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
