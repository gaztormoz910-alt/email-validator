#!/usr/bin/env python
import argparse
import contextlib
import csv
import io
import json
import os
import re
import signal
import sys
import threading
import time

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
    "verdict_confidence", "verdict_basis", "provider",
    "domain_type", "name_source", "gender_source", "country_source",
    "company_source", "job_role_source", "validated_at",
    "role_address",
    "suggested_email",
    "typo_of",
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
        "role_address": "да" if data.get("role_address") else "",
        "suggested_email": data.get("suggested_email", ""),
        "typo_of": data.get("typo_of", ""),
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


def revise_rows(results, lock, domains, new_status, note, spare=None):
    wanted = {"@" + str(d).strip().lower().lstrip("@") for d in domains or []}
    moved = 0
    with lock:
        for row in results:
            if row["status"] != "Valid":
                continue
            if not any(row["email"].lower().endswith(suffix) for suffix in wanted):
                continue
            if spare and row["email"].strip().lower() in spare:
                continue
            row["reason"] = ("%s | %s" % (row["reason"], note)).strip(" |")
            if new_status:
                row["status"] = new_status
            moved += 1
    return moved


def cmd_validate(args):
    if not os.path.exists(args.emails):
        print(f"Файла с адресами нет: {args.emails}", file=sys.stderr)
        return 1

    sources = [{"type": "file", "path": args.emails}]

    if args.scan_only:
        for line in format_base_scan(scan_base_providers(sources)):
            print(line)
        return 0

    proxies = []
    if args.proxies:
        if not os.path.exists(args.proxies):
            print(f"Файла с прокси нет: {args.proxies}", file=sys.stderr)
            return 1
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

    def on_revise(domains, new_status, note, spare=None):
        return revise_rows(results, lock, domains, new_status, note, spare)

    progress_open = [False]
    print_lock = threading.Lock()

    def on_log(message, tag="info"):
        if not args.quiet:
            with print_lock:
                if progress_open[0]:
                    print(file=sys.stderr)
                    progress_open[0] = False
                print(time.strftime("%H:%M:%S"), message, file=sys.stderr, flush=True)

    def on_progress(current, total):
        if args.quiet or not total:
            return
        with print_lock:
            print(f"\r{current}/{total} ({current * 100 // total}%)",
                  end="", file=sys.stderr, flush=True)
            progress_open[0] = True

    pipeline = ValidationPipeline(callbacks={
        "on_log": on_log,
        "on_result": on_result,
        "on_progress": on_progress,
        "on_revise": on_revise,
        "on_complete": done.set,
    })

    for line in format_base_scan(scan_base_providers(sources)):
        on_log(line)

    from core.activity import Pulse
    pulse = Pulse(pipeline.activity, emit=lambda text, tag: on_log(text, tag))

    сбой = []

    def прогон():
        try:
            pipeline.confirm_valid = not args.no_confirm_valid
            pipeline.setup(timeout=args.timeout, enable_ai=not args.no_ai,
                           proxies=proxies, threads=args.threads,
                           use_cache=not args.no_cache)
            pipeline.run_pipeline(sources, threads=args.threads, fix_typos=True,
                                  check_spam=True, deep_ping=True,
                                  enable_ai=not args.no_ai,
                                  enable_osint=not args.no_osint,
                                  resume=not args.no_resume)
        except BaseException as exc:
            сбой.append(exc)

    поток = threading.Thread(target=прогон, name="cli-run", daemon=True)

    прервано = False
    сразу = False
    нажатия = []
    прежний_sigint = None
    слушаем = threading.current_thread() is threading.main_thread()

    def _на_ctrl_c(signum, frame):
        нажатия.append(signum)

    def вернуть_прежний():
        if слушаем:
            try:
                signal.signal(signal.SIGINT, прежний_sigint
                              if прежний_sigint is not None
                              else signal.default_int_handler)
            except (ValueError, OSError):
                pass

    if слушаем:
        try:
            прежний_sigint = signal.getsignal(signal.SIGINT)
            if прежний_sigint == signal.SIG_IGN:
                слушаем = False
            else:
                signal.signal(signal.SIGINT, _на_ctrl_c)
        except (ValueError, OSError):
            слушаем = False

    дошли = False
    try:
        pipeline.activity.begin()
        pulse.start()
        поток.start()
        while поток.is_alive():
            поток.join(0.25)
            if нажатия and not прервано:
                прервано = True
                pipeline.stop()
                print("\nПрервано. Доделываю начатые проверки и сохраняю результат "
                      "(Ctrl+C ещё раз — выйти сразу).", file=sys.stderr)
            if len(нажатия) >= 2:
                сразу = True
                print("\nВыхожу сразу: записываю то, что уже проверено.", file=sys.stderr)
                pipeline._finish_activity(interrupted=True)
                break
        if сбой and isinstance(сбой[0], KeyboardInterrupt):
            if not прервано:
                pipeline.stop()
                print("\nПрервано. Сохраняю то, что успели проверить.", file=sys.stderr)
            pipeline._finish_activity(interrupted=True)
        elif сбой:
            raise сбой[0]
        дошли = True
    except Exception as exc:
        on_log("[DEAD] Проверка прервана ошибкой: %s: %s"
               % (type(exc).__name__, exc), "dead")
        pipeline._finish_activity(failed=True)
        raise
    finally:
        итог_подведён = False
        try:
            pipeline._finish_activity()
            pulse.stop()
            итог_подведён = True
        finally:
            if дошли and итог_подведён and слушаем:
                try:
                    signal.signal(signal.SIGINT, signal.SIG_IGN)
                except (ValueError, OSError):
                    вернуть_прежний()
            else:
                вернуть_прежний()
    try:
        if not args.quiet:
            print(file=sys.stderr)

        if getattr(pipeline, "blocked_reason", ""):
            вернуть_прежний()
            print("Проверка не выполнялась: %s. Подробности — в строках [DEAD] выше."
                  % pipeline.blocked_reason, file=sys.stderr)
            return 3
    except BaseException:
        вернуть_прежний()
        raise

    исходный = None
    if слушаем:
        исходный = (прежний_sigint if прежний_sigint is not None
                    else signal.default_int_handler)
    with _без_прерываний(вернуть=исходный):
        if not сразу:
            return _записать_итог(args, pipeline, results, lock, done, on_log,
                                  прервано, сразу)
        try:
            return _записать_итог(args, pipeline, results, lock, done, on_log,
                                  прервано, сразу)
        except BaseException:
            try:
                import traceback
                traceback.print_exc()
            finally:
                _выйти_сразу(1)
            raise


def _записать_итог(args, pipeline, results, lock, done, on_log, прервано, сразу):
    if сразу:
        lock.acquire()
        снимок = list(results)
    else:
        with lock:
            снимок = list(results)
    rows = [_row(entry) for entry in снимок]

    if args.status:
        wanted = {s.strip().lower() for s in args.status.split(",")}
        rows = [r for r in rows if r["status"].lower() in wanted]

    if args.min_score:
        rows = [r for r in rows
                if isinstance(r["score"], int) and r["score"] >= args.min_score]

    if args.suppress:
        from core.cleaner import normalize_for_dedup
        drop = baseops.suppression_keys(args.suppress)
        before = len(rows)
        rows = [r for r in rows if normalize_for_dedup(r["email"]) not in drop]
        on_log(f"[INFO] Вычтено по списку отписок: {before - len(rows)}")

    written, saved = baseops.write_chunks_stream(
        iter(rows), args.out, args.chunk, _make_writer(args.format))
    for path in written:
        print(path)
    on_log(f"[INFO] Записано строк: {saved}")

    counts = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    on_log("[INFO] Итог: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    код = 0 if done.is_set() and pipeline.activity.state == "done" and not прервано else 2
    if сразу:
        _выйти_сразу(код)
    return код


@contextlib.contextmanager
def _без_прерываний(вернуть=None):
    поставлен = False
    прежний = None
    if threading.current_thread() is threading.main_thread():
        try:
            прежний = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            поставлен = True
        except (ValueError, OSError):
            поставлен = False
    try:
        yield
    finally:
        if поставлен:
            итог = вернуть if вернуть is not None else прежний
            signal.signal(signal.SIGINT, итог if итог is not None
                          else signal.default_int_handler)


def _выйти_сразу(код):
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    os._exit(код)


_BOUNCE_CODE_RE = re.compile(
    r"(?<![\d.])(?:([45]\d\d)(?:[ -]+([45]\.\d{1,3}\.\d{1,3}))?"
    r"|([45]\.\d{1,3}\.\d{1,3}))(?![\d.]*\d)")


def _bounce_is_hard(строка):
    from core.smtp_codes import classify_smtp_response

    найдено = _BOUNCE_CODE_RE.search(строка)
    if not найдено:
        return None
    трёхзначный, расширенный, голый = найдено.groups()
    if трёхзначный:
        код = int(трёхзначный)
    else:
        код = 550 if голый.startswith("5") else 450
    вердикт = classify_smtp_response(код, строка[найдено.start():])
    return вердикт.get("status") == "invalid"


def cmd_bounces(args):
    from core.cache import ResultCache
    from core.email_syntax import harvest_pattern

    образец = harvest_pattern()
    адреса, пропущено = [], 0
    без_кода = не_жёсткие = 0
    with io.open(args.report, encoding="utf-8", errors="replace") as handle:
        for строка in handle:
            if args.hard_only and args.hard_only.lower() not in строка.lower():
                пропущено += 1
                continue
            найдено = образец.findall(строка)
            if найдено and not args.hard_only:
                жёсткий = _bounce_is_hard(строка)
                if жёсткий is None:
                    без_кода += 1
                    continue
                if not жёсткий:
                    не_жёсткие += 1
                    continue
            адреса.extend(найдено)

    def сказать_о_пропущенных():
        if не_жёсткие:
            print("Пропущено строк с мягким или неясным отказом (переполнен, "
                  "занят, политика, отказ отправителю): %d — ящик за ними может "
                  "быть живым." % не_жёсткие)
        if без_кода:
            print("Пропущено строк без кода ответа сервера: %d — жёсткий это "
                  "отскок или мягкий, по строке не понять. Если файл содержит "
                  "только жёсткие отскоки, задайте --hard-only со словом, "
                  "которое есть в этих строках." % без_кода)

    if not адреса:
        сказать_о_пропущенных()
        print("В файле не нашлось ни одного адреса с доказанным отскоком — "
              "проверьте формат.")
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
    сказать_о_пропущенных()
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
                        "жёсткие отскоки от мягких, например --hard-only 5.1.1; "
                        "без него берутся строки, где код ответа сам говорит "
                        "«ящика нет»")
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
    from core.nullstream import readable_output
    readable_output()
    try:
        from core.crashlog import install_hooks
        install_hooks()
    except Exception:
        pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
