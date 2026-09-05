#!/usr/bin/env python
# cli.py
"""Валидатор без графического окна — для скриптов и пайплайнов.

Раньше запуск был возможен только из GUI, и встроить проверку во что-либо
внешнее было нельзя. Здесь тот же движок, те же прокси, тот же кэш —
разница лишь в том, что результат уходит в файл, а прогресс в stderr.

    python cli.py validate --emails base.txt --proxies socks5.txt -o out.csv
    python cli.py validate --emails base.txt --proxies p.txt -o out.txt \\
        --suppress unsubscribed.txt --chunk 50000
    python cli.py subtract base.txt unsubscribed.txt -o clean.txt
    python cli.py merge a.txt b.txt -o all.txt
    python cli.py intersect a.txt b.txt -o both.txt

Коды возврата: 0 — успех, 1 — ошибка запуска, 2 — прогон прерван.
"""

import argparse
import csv
import io
import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import baseops
from core.pipeline import ValidationPipeline
from core.provider import format_base_scan, scan_base_providers
from core.encoding import open_text

EXPORT_FIELDS = [
    "email", "original_email",
    "status", "reason", "mx", "name", "first_name", "last_name",
    "gender", "country",
    "birth_year", "company", "job_role", "score", "grade",
    # Уверенность в ВЕРДИКТЕ и её основание — отдельно от скора живости.
    "verdict_confidence", "verdict_basis", "provider",
    "domain_type", "name_source", "gender_source", "country_source",
    "company_source", "job_role_source", "validated_at",
]


def _row(entry):
    data = entry["data"]
    return {
        "email": entry["email"],
        "status": entry["status"],
        "reason": entry["reason"],
        "mx": entry["mx"],
        "name": data.get("name", ""),
        "first_name": data.get("first_name", ""),
        "last_name": data.get("last_name", ""),
        "gender": data.get("gender", ""),
        "country": data.get("country", ""),
        "birth_year": data.get("birth_year", ""),
        "company": data.get("company", ""),
        "job_role": data.get("job_role", ""),
        "original_email": data.get("original_email", ""),
        "score": data.get("engagement_score", ""),
        "grade": data.get("engagement_grade", ""),
        # Уверенность в вердикте и её основание: без них колонки в заголовке
        # были бы, а значений в них — нет.
        "verdict_confidence": data.get("verdict_confidence", ""),
        "verdict_basis": data.get("verdict_basis", ""),
        "provider": data.get("provider_name", ""),
        "domain_type": data.get("domain_type", ""),
        "name_source": data.get("name_source", ""),
        "gender_source": data.get("gender_source", ""),
        "country_source": data.get("country_source", ""),
        "company_source": data.get("company_source", ""),
        "job_role_source": data.get("job_role_source", ""),
        "validated_at": data.get("validated_at", ""),
    }


def _make_writer(fmt):
    def write_csv(handle, rows):
        writer = csv.DictWriter(handle, fieldnames=EXPORT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    def write_txt(handle, rows):
        for row in rows:
            handle.write(row["email"] + "\n")

    def write_json(handle, rows):
        json.dump(rows, handle, ensure_ascii=False, indent=2)

    return {"csv": write_csv, "txt": write_txt, "json": write_json}[fmt]


def cmd_validate(args):
    if not os.path.exists(args.emails):
        print(f"Файла с адресами нет: {args.emails}", file=sys.stderr)
        return 1

    sources = [{"type": "file", "path": args.emails}]

    # Скан состава базы не делает ни одного сетевого запроса, поэтому и прокси
    # ему не нужны — проверять их раньше означало бы отказать без причины.
    if args.scan_only:
        for line in format_base_scan(scan_base_providers(sources)):
            print(line)
        return 0

    proxies = []
    if args.proxies:
        if not os.path.exists(args.proxies):
            print(f"Файла с прокси нет: {args.proxies}", file=sys.stderr)
            return 1
        # errors="ignore" молча выбрасывал байты; список прокси обычно
        # в ASCII, но комментарий по-русски в нём — обычное дело.
        with open_text(args.proxies) as f:
            proxies = [line.strip() for line in f if line.strip()]
        if not proxies:
            print("Список прокси пуст.", file=sys.stderr)
            return 1
    elif not args.allow_direct:
        print("Прокси не заданы. Прямое соединение раскроет твой реальный IP "
              "почтовым серверам. Если это осознанно — добавь --allow-direct.",
              file=sys.stderr)
        return 1

    results = []
    lock = threading.Lock()
    done = threading.Event()

    def on_result(email, status, reason, mx, data):
        with lock:
            results.append({"email": email, "status": status, "reason": reason,
                            "mx": mx, "data": dict(data)})

    def on_revise(domains, new_status, note):
        """Пересмотр уже собранных строк по разоблачённым доменам.

        Командная строка держит результаты в памяти и пишет их в конце —
        значит пересмотр обязан дойти и сюда, иначе в файле останется
        «Годен» по домену, который принимает что угодно.
        """
        wanted = {"@" + str(d).strip().lower().lstrip("@") for d in domains or []}
        moved = 0
        with lock:
            for row in results:
                if row["status"] != "Valid":
                    continue
                if not any(row["email"].lower().endswith(suffix) for suffix in wanted):
                    continue
                row["reason"] = ("%s | %s" % (row["reason"], note)).strip(" |")
                if new_status:
                    row["status"] = new_status
                moved += 1
        return moved

    def on_log(message, tag="info"):
        if not args.quiet:
            print(message, file=sys.stderr)

    def on_progress(current, total):
        if args.quiet or not total:
            return
        print(f"\r{current}/{total} ({current * 100 // total}%)",
              end="", file=sys.stderr, flush=True)

    pipeline = ValidationPipeline(callbacks={
        "on_log": on_log,
        "on_result": on_result,
        "on_progress": on_progress,
        "on_revise": on_revise,
        "on_complete": done.set,
    })

    for line in format_base_scan(scan_base_providers(sources)):
        on_log(line)

    try:
        # confirm_valid ставится ПОЛЕМ, а не параметром: run_pipeline его не
        # принимает, а читает у объекта. Флаг был объявлен и никуда не
        # подключён — из командной строки второе мнение не работало вовсе.
        pipeline.confirm_valid = not args.no_confirm_valid
        pipeline.setup(timeout=args.timeout, enable_ai=not args.no_ai,
                       proxies=proxies, threads=args.threads,
                       use_cache=not args.no_cache)
        pipeline.run_pipeline(sources, threads=args.threads, fix_typos=True,
                              check_spam=True, deep_ping=True,
                              enable_ai=not args.no_ai,
                              enable_osint=not args.no_osint,
                              resume=not args.no_resume)
    except KeyboardInterrupt:
        pipeline.stop()
        print("\nПрервано. Сохраняю то, что успели проверить.", file=sys.stderr)
    if not args.quiet:
        print(file=sys.stderr)

    rows = [_row(entry) for entry in results]

    if args.status:
        wanted = {s.strip().lower() for s in args.status.split(",")}
        rows = [r for r in rows if r["status"].lower() in wanted]

    if args.min_score:
        rows = [r for r in rows
                if isinstance(r["score"], int) and r["score"] >= args.min_score]

    # Список отписок вычитается ВСЕГДА перед записью: повторное письмо тому,
    # кто уже отписался, стоит жалобы на спам.
    if args.suppress:
        # Сравнение по КАНОНИЧЕСКОМУ ключу — тому же, которым идёт дедуп.
        # Человек отписался как John.Doe@Gmail.com, а в базе лежит
        # johndoe@gmail.com: это один ящик, и сверка по сырой строке отправит
        # ему письмо снова. Раньше здесь строился промежуточный список через
        # subtract() и множество по .lower() — три прохода и лишняя копия
        # базы в памяти ради того же результата.
        from core.cleaner import normalize_for_dedup
        drop = baseops.suppression_keys(args.suppress)
        before = len(rows)
        rows = [r for r in rows if normalize_for_dedup(r["email"]) not in drop]
        on_log(f"[INFO] Вычтено по списку отписок: {before - len(rows)}")

    # Потоковая запись: на большой базе строки не собираются в памяти дважды.
    written, saved = baseops.write_chunks_stream(
        iter(rows), args.out, args.chunk, _make_writer(args.format))
    for path in written:
        print(path)
    on_log(f"[INFO] Записано строк: {saved}")

    counts = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    on_log("[INFO] Итог: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 0 if done.is_set() else 2


def cmd_bounces(args):
    """Кладёт адреса из отчёта об отскоках в кэш как доказанный Invalid.

    ЗАЧЕМ ЭТО СИЛЬНЕЕ SMTP-ПРОБЫ. `RCPT TO` спрашивает сервер о НАМЕРЕНИИ
    принять письмо. Отскок означает, что письмо приняли, донесли до почтового
    ящика и отвергли ТАМ. Между этими двумя событиями стоит вся внутренняя
    маршрутизация получателя, о которой снаружи не знает никто. Поэтому
    запись идёт поверх всего, даже поверх свежего «Годен».

    ТОЛЬКО ЖЁСТКИЕ ОТСКОКИ. Мягкий (ящик переполнен, сервер занят, серый
    список) доказывает ОБРАТНОЕ — что адрес существует и им пользуются, — и
    записав его как Invalid, владелец выбросил бы лучшие свои контакты.
    Разделить их за него нельзя: формат отчёта у каждого рассыльщика свой.
    Поэтому фильтр по строке отдаётся ему (`--hard-only`), а по умолчанию
    берётся весь файл — с явным предупреждением в выводе.
    """
    from core.cache import ResultCache
    from core.email_syntax import harvest_pattern

    образец = harvest_pattern()
    адреса, пропущено = [], 0
    with io.open(args.report, encoding="utf-8", errors="replace") as handle:
        for строка in handle:
            if args.hard_only and args.hard_only.lower() not in строка.lower():
                пропущено += 1
                continue
            найдено = образец.findall(строка)
            адреса.extend(найдено)

    if not адреса:
        print("В файле не нашлось ни одного адреса — проверьте формат.")
        return 1

    уникальные = sorted(set(a.lower() for a in адреса))
    if args.dry_run:
        print("Нашлось адресов: %d (уникальных %d). Ничего не записано — "
              "это пробный прогон." % (len(адреса), len(уникальные)))
        for адрес in уникальные[:10]:
            print("   " + адрес)
        return 0

    cache = ResultCache()
    try:
        записано = cache.import_bounces(уникальные, detail=args.note or "")
        подозрительные = cache.bounced_domains(min_count=args.domain_min)
    finally:
        cache.close()

    print("Записано отскоков: %d из %d уникальных адресов." % (записано, len(уникальные)))
    if пропущено:
        print("Пропущено строк без метки %r: %d" % (args.hard_only, пропущено))
    if not args.hard_only:
        print("ВНИМАНИЕ: фильтра по жёсткости не было. Если в файле есть "
              "мягкие отскоки (переполнен, занят, серый список), они записаны "
              "как Invalid ошибочно — такой адрес живой. Задайте --hard-only.")
    if подозрительные:
        print()
        print("Домены с %d и более отскоками — кандидаты в catch-all:"
              % args.domain_min)
        for домен in подозрительные:
            print("   " + домен)
    return 0


def cmd_baseop(args):
    left = baseops.read_emails(args.left)
    right = baseops.read_emails(args.right) if args.right else []
    if not left:
        print(f"Пусто или файла нет: {args.left}", file=sys.stderr)
        return 1

    operation = {"merge": baseops.merge if args.right else None,
                 "subtract": baseops.subtract,
                 "intersect": baseops.intersect}[args.command]
    result = (baseops.merge(left, right) if args.command == "merge"
              else operation(left, right))

    written = baseops.write_chunks(
        result, args.out, args.chunk,
        lambda handle, rows: handle.writelines(e + "\n" for e in rows))
    for path in written:
        print(path)
    print(f"{len(left)} и {len(right)} -> {len(result)}", file=sys.stderr)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cli.py", description="Валидация email-баз без графического окна")
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("validate", help="проверить базу")
    v.add_argument("--emails", required=True, help="файл с адресами")
    v.add_argument("--proxies", help="файл со SOCKS5-прокси")
    v.add_argument("-o", "--out", default="results.csv", help="куда писать")
    v.add_argument("--format", choices=("csv", "txt", "json"), default="csv")
    v.add_argument("--threads", type=int, default=100)
    v.add_argument("--timeout", type=int, default=15)
    v.add_argument("--chunk", type=int, default=0, help="резать выгрузку по N строк")
    v.add_argument("--suppress", help="файл отписок — вычесть перед записью")
    v.add_argument("--status", help="оставить только эти статусы через запятую")
    v.add_argument("--min-score", type=int, default=0)
    # ПЯТЬ НАСТРОЕК КАЧЕСТВА ВКЛЮЧЕНЫ, выключаются флагом --no-*.
    #
    # Так же, как в окне: владелец не хочет включать их вручную, а забытая
    # настройка — это молча ухудшенный результат. Прежние --ai и --osint
    # означали обратное (по умолчанию выключено), и командная строка
    # работала хуже окна при тех же данных.
    v.add_argument("--no-ai", action="store_true",
                   help="не отсеивать адреса-роботы (ML-обогащение выключено)")
    v.add_argument("--no-osint", action="store_true",
                   help="не искать имя, пол и страну")
    v.add_argument("--no-cache", action="store_true", help="не брать вердикты из кэша")
    v.add_argument("--no-resume", action="store_true",
                   help="не продолжать прерванный прогон, начать с нуля")
    v.add_argument("--no-confirm-valid", action="store_true",
                   help="не перепроверять «Годен» вторым прокси "
                        "(вдвое быстрее, но почтовик, который врёт только "
                        "нашему выходу, останется незамеченным)")
    v.add_argument("--scan-only", action="store_true",
                   help="только показать состав базы, без единого запроса")
    v.add_argument("--allow-direct", action="store_true",
                   help="разрешить работу без прокси (реальный IP будет виден)")
    v.add_argument("--quiet", action="store_true")
    v.set_defaults(func=cmd_validate)

    b = sub.add_parser("bounces",
                       help="загрузить отчёт об отскоках в кэш вердиктов")
    b.add_argument("report", help="файл отчёта рассыльщика (любой текст)")
    b.add_argument("--hard-only", metavar="СЛОВО",
                   help="брать только строки с этим словом — так отделяются "
                        "жёсткие отскоки от мягких, например --hard-only 5.1.1")
    b.add_argument("--note", default="",
                   help="пометка, которая ляжет в причину вердикта")
    b.add_argument("--domain-min", type=int, default=3,
                   help="со скольких отскоков домен считается подозрительным")
    b.add_argument("--dry-run", action="store_true",
                   help="показать, что нашлось, и ничего не записывать")
    b.set_defaults(func=cmd_bounces)

    for name, help_text in (("merge", "объединить два списка"),
                            ("subtract", "вычесть второй список из первого"),
                            ("intersect", "оставить только общие адреса")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("left")
        p.add_argument("right", nargs="?" if name == "merge" else None)
        p.add_argument("-o", "--out", default="out.txt")
        p.add_argument("--chunk", type=int, default=0)
        p.set_defaults(func=cmd_baseop)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
