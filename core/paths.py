# -*- coding: utf-8 -*-
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ПОСТАВЛЯЕМЫЕ = ("free_providers.txt", "disposable.txt",
                "disposable_extra.txt", "disposable_more.txt")


def is_frozen():
    return bool(getattr(sys, "frozen", False))


def bundle_dir():
    return getattr(sys, "_MEIPASS", ROOT)


def resource_path(*parts):
    return os.path.join(bundle_dir(), *parts)


def app_dir():
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return ROOT


def data_dir():
    свой = os.environ.get("MAILFACT_DATA_DIR")
    путь = свой.strip() if isinstance(свой, str) and свой.strip() else os.path.join(app_dir(), "data")
    try:
        os.makedirs(путь, exist_ok=True)
    except OSError:
        pass
    return путь


def data_path(*parts):
    return os.path.join(data_dir(), *parts)


def seed_data():
    if not is_frozen():
        return []
    куда = data_dir()
    скопировано = []
    for имя in ПОСТАВЛЯЕМЫЕ:
        цель = os.path.join(куда, имя)
        if os.path.exists(цель):
            continue
        исток = resource_path("data", имя)
        if not os.path.exists(исток):
            continue
        try:
            shutil.copyfile(исток, цель)
            скопировано.append(имя)
        except OSError:
            pass
    return скопировано


def app_version():
    try:
        with open(resource_path("VERSION"), encoding="utf-8") as f:
            текст = f.read().strip()
        return текст or "0.0.0"
    except OSError:
        return "0.0.0"
