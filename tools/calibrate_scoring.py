#!/usr/bin/env python
"""Калибровка весов скоринга по реальному bounce-логу.

Зачем. Веса в core/scoring.py выставлены рукой и до сих пор ни разу не
сверялись с тем, что происходит после рассылки. Это единственное место
скоринга, про которое честно нельзя сказать «измерено». Здесь оно измеряется.

Как. На вход идут две вещи:

  * выгрузка валидатора (CSV с колонками email и signals либо score),
  * bounce-лог рассылки (CSV, где для каждого адреса известно, отскочил он
    или нет).

Для каждого сигнала считается доля отскоков среди адресов, где сигнал
СРАБОТАЛ, и среди тех, где не срабатывал. Разница между ними — это и есть
наблюдаемая сила сигнала:

    lift = bounce_rate_без_сигнала - bounce_rate_с_сигналом

Положительный lift означает, что сигнал предсказывает живой адрес, и его вес
должен быть положительным; отрицательный — наоборот. Новый вес получается
масштабированием lift, а не подгонкой к желаемому результату.

Чего инструмент НЕ делает и почему:

  * не трогает сигнал, по которому меньше MIN_SAMPLES наблюдений в любой из
    двух групп. На двадцати адресах «измеренная» разница — это шум, и заменить
    ею обдуманное значение хуже, чем оставить как есть;
  * не выходит за диапазон +-MAX_WEIGHT, чтобы одна аномальная выгрузка не
    сломала шкалу;
  * не перезаписывает smtp_valid и smtp_valid_full_inbox: вердикт SMTP это не
    статистический признак, а прямое доказательство, и его вес — решение
    владельца, а не следствие одной рассылки.

Запуск:

    python tools/calibrate_scoring.py --results out.csv --bounces bounced.csv
    python tools/calibrate_scoring.py --results out.csv --bounces b.csv --dry-run
"""

import argparse
import csv
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scoring import DEFAULT_WEIGHTS, WEIGHTS_PATH

# Без этого скрипт падает в консоли cp1252 на первом же русском символе
# и работает только там, где вручную выставлен PYTHONIOENCODING.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Меньше этого числа наблюдений в группе — сигнал не калибруется.
MIN_SAMPLES = 50

# Потолок веса. Держит шкалу в тех же порядках, что и значения по умолчанию.
MAX_WEIGHT = 70

# Во сколько раз наблюдаемая разница долей превращается в баллы.
# 100 означает: сигнал, снижающий отскоки на 20 процентных пунктов, весит +20.
LIFT_SCALE = 100

# Сигналы, которые калибровке не подлежат — см. заголовок файла.
FROZEN = ("smtp_valid", "smtp_valid_full_inbox")

# Текст сигнала в выгрузке -> ключ веса. Сигналы пишутся в колонку signals
# человеческим текстом, и связать их с ключами можно только по нему.
SIGNAL_PATTERNS = {
    "gravatar": "есть gravatar",
    "corporate_domain": "корпоративный домен",
    "dns_full": "полный dns",
    "dns_good": "хороший dns",
    "dns_basic": "базовый dns",
    "domain_old_5y": "домен старше 5 лет",
    "domain_old_1y": "домен старше 1 года",
    "name_extracted": "имя извлечено",
    "disposable": "одноразовый",
    "domain_young_30d": "молодой домен (< 30",
    "domain_young_90d": "молодой домен (< 90",
    "role_based": "role-based",
    "server_outdated": "устаревший почтовый сервер",
    "in_dnsbl": "чёрных списках",
    "no_ptr": "нет ptr-записи",
    "no_starttls": "нет шифрования",
    "no_website": "нет живого сайта",
    "machine_generated": "сгенерированный машиной",
    "parked_domain": "припаркован",
    "smtp_risky": "risky (возможно жива)",
    "smtp_unknown": "unknown (неопредел",
}

_TRUE = {"1", "true", "yes", "y", "да", "bounce", "bounced", "hard", "soft"}


def _norm(email):
    return (email or "").strip().lower()


def read_bounces(path):
    """Множество отскочивших адресов и множество всех адресов рассылки.

    Формат гибкий: либо колонка со статусом (bounced/1/yes), либо просто
    список адресов — тогда все они считаются отскочившими.
    """
    bounced, seen = set(), set()
    with open(path, "r", encoding="utf-8", errors="ignore", newline="") as handle:
        sample = handle.read(4096)
        handle.seek(0)
        has_header = bool(re.search(r"(?i)\bemail\b", sample.split("\n")[0] if sample else ""))
        if has_header:
            for row in csv.DictReader(handle):
                key = None
                for name in row:
                    if name and name.strip().lower() in ("email", "e-mail", "address"):
                        key = name
                        break
                if not key:
                    continue
                email = _norm(row.get(key))
                if not email:
                    continue
                seen.add(email)
                status = ""
                for name, value in row.items():
                    if name and name.strip().lower() in ("bounced", "bounce", "status", "result"):
                        status = str(value or "").strip().lower()
                        break
                if not status or status in _TRUE:
                    bounced.add(email)
        else:
            for line in handle:
                email = _norm(line.split(",")[0])
                if email:
                    seen.add(email)
                    bounced.add(email)
    return bounced, seen


def read_results(path):
    """[(email, {ключи сработавших сигналов})] из выгрузки валидатора."""
    rows = []
    with open(path, "r", encoding="utf-8", errors="ignore", newline="") as handle:
        for row in csv.DictReader(handle):
            email = ""
            signals_text = ""
            for name, value in row.items():
                if not name:
                    continue
                low = name.strip().lower()
                if low in ("email", "e-mail", "address"):
                    email = _norm(value)
                elif low in ("signals", "signal", "reason", "причина"):
                    signals_text += " " + str(value or "")
            if not email:
                continue
            text = signals_text.lower()
            fired = {key for key, needle in SIGNAL_PATTERNS.items() if needle in text}
            rows.append((email, fired))
    return rows


def calibrate(results, bounced, mailed):
    """Считает новые веса. Возвращает (weights, report).

    weights содержит ТОЛЬКО изменённые ключи: всё, по чему данных не хватило,
    остаётся прежним, а не подменяется нулём.
    """
    observed = [(email, fired) for email, fired in results if email in mailed]
    weights, report = {}, []

    for key in DEFAULT_WEIGHTS:
        if key in FROZEN or key not in SIGNAL_PATTERNS:
            continue
        with_hits = [e for e, f in observed if key in f]
        without_hits = [e for e, f in observed if key not in f]
        if len(with_hits) < MIN_SAMPLES or len(without_hits) < MIN_SAMPLES:
            report.append({"signal": key, "changed": False,
                           "reason": f"наблюдений мало: {len(with_hits)} и {len(without_hits)}"})
            continue

        rate_with = sum(1 for e in with_hits if e in bounced) / len(with_hits)
        rate_without = sum(1 for e in without_hits if e in bounced) / len(without_hits)
        lift = rate_without - rate_with
        new_weight = int(round(lift * LIFT_SCALE))
        new_weight = max(-MAX_WEIGHT, min(MAX_WEIGHT, new_weight))

        weights[key] = new_weight
        report.append({
            "signal": key,
            "changed": new_weight != DEFAULT_WEIGHTS[key],
            "old": DEFAULT_WEIGHTS[key],
            "new": new_weight,
            "bounce_with": round(rate_with, 4),
            "bounce_without": round(rate_without, 4),
            "samples": [len(with_hits), len(without_hits)],
        })

    return weights, report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--results", required=True, help="CSV выгрузки валидатора")
    parser.add_argument("--bounces", required=True, help="CSV bounce-лога рассылки")
    parser.add_argument("-o", "--out", default=WEIGHTS_PATH, help="куда положить веса")
    parser.add_argument("--dry-run", action="store_true", help="посчитать, но не писать")
    args = parser.parse_args(argv)

    for path in (args.results, args.bounces):
        if not os.path.exists(path):
            print(f"Файла нет: {path}", file=sys.stderr)
            return 1

    results = read_results(args.results)
    bounced, mailed = read_bounces(args.bounces)
    if not results or not mailed:
        print("Пустые данные — калибровать нечего.", file=sys.stderr)
        return 1

    weights, report = calibrate(results, bounced, mailed)
    for line in report:
        if line.get("changed"):
            print(f"  {line['signal']}: {line['old']} -> {line['new']} "
                  f"(отскоки {line['bounce_with']:.1%} против {line['bounce_without']:.1%}, "
                  f"n={line['samples'][0]}/{line['samples'][1]})")
        elif not line.get("changed") and "reason" in line:
            print(f"  {line['signal']}: без изменений — {line['reason']}")

    if not weights:
        print("Ни один сигнал не набрал достаточного числа наблюдений. "
              f"Нужно минимум {MIN_SAMPLES} адресов в каждой группе.", file=sys.stderr)
        return 1

    if args.dry_run:
        print(f"\n--dry-run: файл не записан. Изменилось бы весов: {len(weights)}.")
        return 0

    directory = os.path.dirname(args.out)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump({"weights": weights, "report": report}, handle,
                  ensure_ascii=False, indent=2)
    print(f"\nЗаписано в {args.out}: весов {len(weights)}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
