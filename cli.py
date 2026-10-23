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

Коды возврата: 0 — успех, 1 — ошибка запуска, 2 — прогон прерван,
3 — работа не выполнялась (нечем проверять: порт 25 закрыт или ни один
прокси не ожил).
"""

import argparse
import contextlib
import csv
import io
import json
import os
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
    # Уверенность в ВЕРДИКТЕ и её основание — отдельно от скора живости.
    "verdict_confidence", "verdict_basis", "provider",
    "domain_type", "name_source", "gender_source", "country_source",
    "company_source", "job_role_source", "validated_at",
    # Ролевой адрес (info@, sales@) — признак рядом со статусом, а не сам
    # статус: мёртвый ролевой — «Мёртв», живой — «Role-based».
    "role_address",
    # Похоже на опечатку: какой адрес человек, вероятно, имел в виду. Вердикт
    # в строке остаётся про загруженный адрес. Для домена-опечатки из списка
    # одноразовых (user@gamil.com) подсказка лежала только в карточке окна и
    # в выгрузку не попадала — прогон test.txt 27.09.2026.
    "suggested_email",
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
        "role_address": "да" if data.get("role_address") else "",
        "suggested_email": data.get("suggested_email", ""),
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

    # Строка прогресса пишется через «\r» без перевода строки. Без учёта этого
    # следующая строка журнала приклеивалась к ней хвостом: «1234/5000 (24%)[INFO] …».
    progress_open = [False]
    # Пишут сюда сразу многие потоки: рабочие (прогресс, [DEAD]) и пульс.
    # Без замка строка журнала всё равно ложилась хвостом к прогрессу, если
    # другой поток печатал прогресс между проверкой флага и печатью строки.
    print_lock = threading.Lock()

    def on_log(message, tag="info"):
        if not args.quiet:
            with print_lock:
                if progress_open[0]:
                    print(file=sys.stderr)
                    progress_open[0] = False
                # Время у каждой строки: по консоли сразу видно, свежая она
                # или давняя, то есть идёт ли работа прямо сейчас.
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

    # Пульс в консоль: раз в 15 с строка «что делает и жив ли», чтобы долгая
    # подготовка (перебор прокси, прогрев модели) не выглядела зависанием.
    # Пишется в обход наблюдения — сам пульс событием не считается.
    from core.activity import Pulse
    pulse = Pulse(pipeline.activity, emit=lambda text, tag: on_log(text, tag))

    # Прогон — в своём потоке, а главный ждёт его и слушает Ctrl+C.
    #
    # Ctrl+C считаем САМИ, обработчиком сигнала, а не ловлей KeyboardInterrupt
    # из join(). На Python 3.11 KeyboardInterrupt, оборвавший join(timeout),
    # помечал ЖИВОЙ рабочий поток завершённым (Thread.join отпускал его
    # служебный замок), и is_alive() врал False: главный проскакивал к записи
    # с пустым снимком — доделанная после «Стопа» проверка не попадала в файл,
    # второе нажатие не замечалось вовсе (CI на windows/ubuntu + Python 3.11,
    # седьмая рецензия). В 3.13 join переписан, там этого нет. Наш обработчик
    # исключений не бросает — join больше ничем не обрывается.
    #
    # Раньше прогон шёл в главном потоке, и Ctrl+C вёл себя плохо (рецензия
    # 17.10.2026, третья): на Windows ожидание рабочих потоков без срока
    # (join() внутри run_pipeline) не прерывается, и Ctrl+C доходил только
    # после всего прохода; а пришедший посреди этапа KeyboardInterrupt
    # обрывал его на полуслове. Теперь Ctrl+C — это «Стоп», как в окне:
    # начатое доделывается, неперепроверенное выдаётся как Unknown, конвейер
    # выходит сам. Второй Ctrl+C — выйти сразу.
    сбой = []

    def прогон():
        try:
            # confirm_valid ставится ПОЛЕМ, а не параметром: run_pipeline его
            # не принимает, а читает у объекта. Флаг был объявлен и никуда не
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
        except BaseException as exc:      # решает главный поток, ниже
            сбой.append(exc)

    поток = threading.Thread(target=прогон, name="cli-run", daemon=True)

    прервано = False
    # Второй Ctrl+C — «выйти сразу». Но собранное всё равно пишется в файл:
    # журнал сделанного уже на диске, и потерянные из выдачи адреса следующий
    # запуск счёл бы проверенными (рецензия 17.10.2026, четвёртая).
    сразу = False
    # Нажатия Ctrl+C. Обработчик только дописывает сюда отметку: list.append —
    # одна операция под GIL, без замков. Никаких Event/Lock в обработчике: он
    # исполняется в главном потоке между его же байт-кодами, и если главный в
    # этот миг держит внутренний замок того же Event (внутри wait()/clear()),
    # set() ждал бы сам себя вечно — замок нереентерабельный. Стресс-репро так
    # и зависал, на 3.11 и на 3.13; это тот же класс, что bpo-14976 у Queue.
    нажатия = []
    прежний_sigint = None
    # Обработчик ставится только из главного потока (так требует signal). Из
    # другого (так бывает в тестах) прерывание ловится лишь через сбой ниже.
    слушаем = threading.current_thread() is threading.main_thread()

    def _на_ctrl_c(signum, frame):
        нажатия.append(signum)

    def вернуть_прежний():
        """Снять наш обработчик: поставить тот, что стоял до прогона."""
        if слушаем:
            try:
                signal.signal(signal.SIGINT, прежний_sigint
                              if прежний_sigint is not None
                              else signal.default_int_handler)
            except (ValueError, OSError):
                pass

    # Обработчик ставится ДО запуска пульса и прогона. Раньше он ставился
    # после поток.start(), и Ctrl+C в этот миг бросал KeyboardInterrupt мимо
    # всей обработки: прогон уже шёл, а CLI выходил с трассировкой, без
    # «Стопа» и без файла (проверка 23.10.2026).
    if слушаем:
        try:
            прежний_sigint = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, _на_ctrl_c)
        except (ValueError, OSError):
            слушаем = False

    # Дошёл ли главный до конца ожидания штатно. Только тогда дальше идёт
    # запись результата, и обработчик меняется сразу на SIG_IGN (см. finally).
    дошли = False
    try:
        pipeline.activity.begin()
        pulse.start()
        поток.start()
        # Главный ждёт конца прогона короткими join() и после каждого смотрит
        # на число нажатий: первое — «Стоп» (доделать начатое), второе —
        # «выйти сразу». Реакция на нажатие — не позже чем через 0.25 с.
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
            # Прерывание выброшено самим этапом, а не пришло в главный
            # поток: этап оборван на полуслове — галочка «✓» была бы ложью.
            if not прервано:
                pipeline.stop()
                print("\nПрервано. Сохраняю то, что успели проверить.", file=sys.stderr)
            pipeline._finish_activity(interrupted=True)
        elif сбой:
            raise сбой[0]
        дошли = True
    except Exception as exc:
        # Ошибка внутри — итог «прервано ошибкой», а не «готово». Причина
        # строкой [DEAD] — ДО итога, как в окне: трассировка Python выйдет
        # только после него, и итог «причина в журнале выше» иначе врал бы.
        on_log("[DEAD] Проверка прервана ошибкой: %s: %s"
               % (type(exc).__name__, exc), "dead")
        pipeline._finish_activity(failed=True)
        raise
    finally:
        # Наш обработчик Ctrl+C снимается здесь. Если дальше запись — сразу на
        # SIG_IGN, без промежутка с прежним обработчиком: раньше между его
        # возвратом и _без_прерываний() Ctrl+C снова бросал KeyboardInterrupt,
        # и законченный прогон выходил без файла, хотя журнал сделанного уже
        # на диске (проверка 23.10.2026). Исходный обработчик вернёт
        # _без_прерываний() после записи. Если дальше записи нет (ошибка) —
        # исходный возвращается сразу.
        #
        # Итог «готово / остановлено / не выполнялось» и конец пульса — при
        # любом исходе. Повторный вызов после run_pipeline ничего не делает.
        # Мост SIG_IGN ставится, только если и это прошло: исключение здесь
        # иначе унесло бы с собой SIG_IGN, и Ctrl+C в процессе не работал бы.
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

        # Прогон остановлен до первого адреса (порт 25 закрыт, ни один прокси
        # не ожил). Пустой файл с кодом 0 выглядел бы как законченная проверка
        # базы, в которой просто ничего не нашлось.
        if getattr(pipeline, "blocked_reason", ""):
            вернуть_прежний()
            print("Проверка не выполнялась: %s. Подробности — в строках [DEAD] выше."
                  % pipeline.blocked_reason, file=sys.stderr)
            return 3
    except BaseException:
        вернуть_прежний()
        raise

    # Дальше пишется результат, и Ctrl+C его больше не обрывает: файл,
    # оборванный на полуслове, хуже ожидания в несколько секунд, а журнал
    # сделанного к этому моменту уже на диске — недописанные адреса
    # следующий запуск счёл бы проверенными (рецензия 17.10.2026, пятая).
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
            # Замок результатов удержан до выхода (см. _записать_итог). Если
            # запись упала (файл открыт в Excel, нет папки, полон диск), выход
            # интерпретатора ждал бы потоки пула перепроверки, а те — этот
            # замок: процесс висел бы, и Ctrl+C уже не помогал (рецензия
            # 18.10.2026, шестая). Причина печатается, выход — сразу. Выход —
            # в finally: если упадёт и сама печать (stderr в файл на том же
            # полном диске), процесс всё равно не повиснет (проверка
            # 23.10.2026).
            try:
                import traceback
                traceback.print_exc()
            finally:
                _выйти_сразу(1)
            raise


def _записать_итог(args, pipeline, results, lock, done, on_log, прервано, сразу):
    """Снимок результатов, фильтры, отписки, запись, код возврата."""
    # После второго Ctrl+C поток прогона ещё жив. Замок результатов
    # удерживается до самого выхода: проверка, закончившаяся во время
    # записи, не сможет ни попасть в результаты после снимка, ни быть
    # помеченной сделанной — отметка идёт только после выдачи (on_result).
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
    # 2 — прогон прерван: Ctrl+C или оборванное ошибкой чтение базы. С тех
    # пор как Ctrl+C стал «Стопом», конвейер и после него зовёт on_complete,
    # так что по одному done уже не понять, дошёл ли прогон до конца —
    # частичный файл получал код 0, как законченный (рецензия 17.10.2026).
    код = 0 if done.is_set() and pipeline.activity.state == "done" and not прервано else 2
    if сразу:
        _выйти_сразу(код)
    return код


@contextlib.contextmanager
def _без_прерываний(вернуть=None):
    """Ctrl+C не действует, пока пишется результат.

    Ставится только из главного потока — обработчик сигнала можно менять
    лишь там; вызов из другого потока (так бывает в тестах) идёт без
    защиты. При любом исходе ставится `вернуть`, а если он не задан — тот
    обработчик, что стоял на входе. cmd_validate передаёт исходный: к входу
    сюда стоит уже не он, а SIG_IGN-мост без окна для KeyboardInterrupt."""
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
    """Второй Ctrl+C: выход, не дожидаясь начатых проверок.

    Обычный возврат из main() ждал бы потоки пулов (ThreadPoolExecutor
    присоединяет их при завершении интерпретатора и сначала доделывает всю
    очередь), а поток прогона, пишущий в stderr во время завершения, ронял
    Python с «Fatal Python error: _enter_buffered_busy». Файл с собранным к
    этому моменту уже записан. Вынесено в функцию, чтобы тест мог её
    подменить: настоящий os._exit оборвал бы и сам pytest."""
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    os._exit(код)


def cmd_bounces(args):
    """Кладёт адреса из отчёта об отскоках в кэш как доказанный Invalid.

    ЗАЧЕМ ЭТО СИЛЬНЕЕ SMTP-ПРОБЫ. `RCPT TO` спрашивает сервер о НАМЕРЕНИИ
    принять письмо. Отскок означает, что письмо приняли, донесли до почтового
    ящика и отвергли ТАМ. Между этими двумя событиями стоит вся внутренняя
    маршрутизация получателя, о которой снаружи не знает никто. Поэтому
    запись идёт поверх всего, даже поверх свежего «Годен».

    ТОЛЬКО ЖЁСТКИЕ ОТСКОКИ. Мягкий (ящик переполнен, сервер занят, серый
    список) доказывает ОБРАТНОЕ — что адрес существует, — и записав его как
    Invalid, владелец объявил бы несуществующим ящик, который есть.
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
