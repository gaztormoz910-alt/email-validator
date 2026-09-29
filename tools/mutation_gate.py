# -*- coding: utf-8 -*-
"""Мутационный гейт: ломаем код по одному месту и требуем, чтобы тесты заметили.

Зачем это нужно отдельно от обычного прогона. Зелёный `pytest` означает «тесты
не упали», а не «тесты что-то проверяют». Тест, который не может упасть, зелёный
всегда — и именно он опаснее отсутствующего, потому что создаёт видимость
покрытия. Здесь мы ломаем по одному ключевому месту в коде и смотрим, упадёт ли
набор. Не упал — значит это место не проверяется ничем, и «зелёный CI» про него
просто молчал.

Чем это отличается от прежнего `audit/mutation_test.py`. Тот гонял ВЕСЬ набор на
каждую мутацию (семь минут × число мутаций), пропускал мутацию с устаревшим
якорем словом «ПРОПУСК» и всегда завершался кодом 0. К моменту переноса в CI
семь якорей из восьми уже не находились в коде: гейт напечатал бы «поймано 1 из
1» и прошёл. Здесь устаревший якорь — это ОШИБКА, а не пропуск: сломанный оракул
и отсутствующий тест одинаково означают, что мы ничего не проверили.

Устройство. У каждой мутации свой список файлов-сторожей — те тесты, которые
обязаны её поймать. Сначала гоняем только их (секунды). Если они промолчали,
гоняем весь быстрый круг: мутация, которую не поймал никто, — это дыра в наборе,
и такое утверждение стоит потраченной минуты. Мутация, которую поймал не тот
набор, что ожидался, считается поймана, но об этом говорится вслух: значит
сторож указан неверно.

Исходники восстанавливаются побайтово, и это проверяется md5. Восстановление
висит и на atexit тоже: прерывание в середине не имеет права оставить в рабочей
копии сломанный файл.

Запуск:
    python tools/mutation_gate.py            # весь гейт
    python tools/mutation_gate.py --list     # только показать список мутаций
    python tools/mutation_gate.py M3         # одну мутацию по идентификатору
"""
import atexit
import hashlib
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Успех печатается ОДНИМ решающим словом и только после всех проверок: гейт
# снаружи ищет именно его, а не «кажется, всё хорошо».
SUCCESS_TOKEN = "MUTATION_GATE_OK"

# Быстрый круг набора. Медленные проверки масштаба тут не нужны: они про память
# и скорость, а не про вердикты.
FAST_SUITE = ["-m", "not slow"]


# Каждая мутация — это правдоподобная ошибка, которую ЛЕГКО совершить при
# правке, и каждая меняет ВЕРДИКТ, а не оформление. Поле guards — файлы,
# которые обязаны её поймать.
MUTATIONS = [
    {
        "id": "M1",
        "title": "синтаксис: перестать проверять ГРАММАТИКУ не-ASCII имени ящика",
        "path": "core/email_syntax.py",
        "old": ("    if not local.isascii():\n"
                "        if not _UTF8_LOCAL_RE.match(local):\n"
                "            return False"),
        "new": ("    if not local.isascii():\n"
                "        if not _UTF8_LOCAL_RE.match(local):\n"
                "            pass"),
        # ПОЧЕМУ МУТАЦИЯ ЗАМЕНЕНА. Раньше здесь ломалась строка
        # `if _BAD_SYNTAX_PATTERNS.search(email): return False`, и гейт
        # честно докладывал «дыру в наборе»: поломку не замечал ни один тест.
        # Тестов не хватало не потому, что их забыли написать, — поломка
        # НЕНАБЛЮДАЕМА. Замерено перебором: из 300 000 случайных адресов под
        # это правило попали 37 925, и ни на одном из них вердикт не
        # изменился. Все формы, которые правило ловит (двойная точка, точка
        # с краю, пробел), уже отвергаются грамматикой: `_RFC5322_REGEX` для
        # ASCII, `_UTF8_LOCAL_RE` для не-ASCII, `_LOCAL_ONLY_REGEX` у
        # домена-литерала. Проверены и те три случая, ради которых правило
        # заводилось: `.ведущая-точка@corp.test`, `иван..петров@почта.рф` и
        # `Иван,Мужской,Россия,ivan@gmail.com` — ни один не меняет вердикт.
        # Требовать тест на ненаблюдаемую поломку значит требовать теста,
        # который не может упасть, — ровно то, против чего этот гейт написан.
        #
        # Теперь ломается настоящий сторож. Без грамматики не-ASCII имени
        # целая строка файла `Иван,Мужской,Россия,ivan@gmail.com` признаётся
        # ОДНИМ законным адресом: загрузчик перестаёт дробить её, и владелец
        # теряет имя, пол и страну на всех кириллических файлах разом.
        "guards": ["tests/test_anyorder.py", "tests/test_syntax_bytes.py"],
        "why": "целая строка файла уехала бы в проверку как один адрес",
    },
    {
        "id": "M2",
        "title": "SMTP: «сервер не понял команду» (500-504) считать приговором ящику",
        "path": "core/smtp_codes.py",
        "old": '    if isinstance(code, int) and 500 <= code <= 504:\n        return result("unknown",',
        "new": '    if isinstance(code, int) and 500 <= code <= 504:\n        return result("invalid",',
        "guards": ["tests/test_smtp_parsing.py", "tests/test_smtp_corpus.py",
                   "tests/test_no_false_verdicts.py"],
        "why": "ложный Invalid на живых ящиках — потерянные контакты",
    },
    {
        "id": "M3",
        "title": "SMTP: снять защиту «отказ по политике/репутации — не про ящик»",
        "path": "core/smtp_codes.py",
        "old": "    if policy and (reputation or not proof):",
        "new": "    if False and (reputation or not proof):",
        "guards": ["tests/test_smtp_parsing.py", "tests/test_smtp_corpus.py",
                   "tests/test_no_false_verdicts.py", "tests/test_smtp_extras.py"],
        "why": "отказ нашему IP превратился бы в «ящика нет»",
    },
    {
        "id": "M4",
        "title": "скоринг: перевернуть знак у подтверждённого 250 OK",
        "path": "core/scoring.py",
        "old": '    "smtp_valid": 55,',
        "new": '    "smtp_valid": -55,',
        "guards": ["tests/test_scoring_invariants.py", "tests/test_calibration.py",
                   "tests/test_score_filter_paths.py"],
        "why": "доказанный живой ящик оказался бы внизу выборки",
    },
    {
        "id": "M5",
        "title": "дедуп: перестать схлопывать точки в имени Gmail",
        "path": "core/cleaner.py",
        "old": '    if domain in _GMAIL_DOMAINS:\n        local = local.replace(".", "")',
        "new": '    if domain in _GMAIL_DOMAINS:\n        local = local',
        "guards": ["tests/test_normalization.py", "tests/test_suppression_key.py"],
        "why": "отписавшийся получил бы письмо снова под другим написанием",
    },
    {
        "id": "M6",
        "title": "кэш: разрешить запоминать недоказанные вердикты",
        "path": "core/cache.py",
        "old": 'CACHEABLE_STATUSES = ("Valid", "Invalid/Bounce")',
        "new": 'CACHEABLE_STATUSES = ("Valid", "Invalid/Bounce", "Unknown", "Risky")',
        "guards": ["tests/test_result_cache.py", "tests/test_cache_regressions.py",
                   "tests/test_accuracy.py"],
        "why": "сбой нашей стороны законсервировался бы на месяцы",
    },
    {
        "id": "M7",
        "title": "прокси: разрешить прямое соединение, когда все прокси выбыли",
        "path": "core/network.py",
        "old": "        if proxy is None and self.has_proxies_configured():\n"
               '            return {"status": "unknown", "reason": "All Proxies Dead'
               ' (прямое соединение запрещено)"}',
        "new": "        if False and self.has_proxies_configured():\n"
               '            return {"status": "unknown", "reason": "All Proxies Dead'
               ' (прямое соединение запрещено)"}',
        # Замерено: из трёх прежних сторожей мутацию не ловил ни один, а
        # ловит её test_proxy_ban.py. Неверный сторож стоил полного прогона
        # набора на каждой проверке.
        "guards": ["tests/test_proxy_ban.py"],
        "why": "домашний IP ушёл бы почтовикам, а вердикты стали бы про него",
    },
    {
        "id": "M8",
        "title": "DNS: сбой запроса MX считать доказательством мёртвого домена",
        "path": "core/dns_checks.py",
        "old": "        if dns_failed:\n            return None\n\n"
               "        # Фоллбэк на A-запись",
        "new": "        if dns_failed:\n            return []\n\n"
               "        # Фоллбэк на A-запись",
        "guards": ["tests/test_no_false_verdicts.py", "tests/test_verdict_precision.py",
                   "tests/test_dns_via_proxy.py"],
        "why": "домен целиком уехал бы в Invalid из-за одного таймаута",
    },
    {
        "id": "M9",
        "title": "очистка: вернуть подмену домена по префиксу (снять предохранитель «точка»)",
        "path": "core/cleaner.py",
        "old": "        if m and self._junk_tail(m.group(2)):",
        "new": "        if m:",
        "guards": ["tests/test_accuracy.py", "tests/test_cleaner_roles.py"],
        "why": "вердикт выносился бы про ЧУЖОЙ ящик под именем моего",
    },
    {
        "id": "M10",
        "title": "postmaster: перевернуть проверку честности сервера",
        "path": "core/network.py",
        "old": "            if honored is False:\n"
               '                result["status"] = "risky"',
        "new": "            if honored is True:\n"
               '                result["status"] = "risky"',
        "guards": ["tests/test_second_opinion.py", "tests/test_verdict_precision.py",
                   "tests/test_no_false_verdicts.py"],
        "why": "сервер, отвечающий 550 всем подряд, снова хоронил бы адреса",
    },
    # --- защиты, добавленные по аудиту 27.09.2026 (.unlazy/audit6/АУДИТ.md) ---
    {
        "id": "M11",
        "title": "SMTP: переполненный ящик снова объявить «Годен» (аудит D1)",
        "path": "core/smtp_codes.py",
        "old": '            return result("full", f"{numeric} Ящик переполнен',
        "new": '            return result("valid", f"{numeric} Ящик переполнен',
        "guards": ["tests/test_audit6_fixes.py", "tests/test_smtp_parsing.py"],
        "why": "письмо в переполненный ящик — отскок, а он стоял бы в «Годен»",
    },
    {
        "id": "M12",
        "title": "catch-all: считать исключённым без отказа выдуманному адресу (аудит D2)",
        "path": "core/confirmation.py",
        "old": '        excluded = result.get("control_rcpt") == "rejected"',
        "new": '        excluded = True',
        "guards": ["tests/test_audit6_fixes.py"],
        "why": "catch-all за серым списком снова выдавал бы «Годен» на выдуманный адрес",
    },
    {
        "id": "M13",
        "title": "лестница после вердикта: не пускать канарейку (аудит D3)",
        "path": "core/settle.py",
        "old": ('        if raw_status == "valid":\n'
                "            self._fly_canary(email, res)"),
        "new": ("        if False:\n"
                "            self._fly_canary(email, res)"),
        "guards": ["tests/test_audit6_fixes.py", "tests/test_canary.py"],
        "why": "тарпитинг посреди прогона снова оставлял бы «Годен» недоказанным",
    },
    {
        "id": "M14",
        "title": "роль снова прячет SMTP-вердикт (аудит D8)",
        "path": "core/settle.py",
        "old": '        if is_role and status_display == "Valid":',
        "new": '        if is_role:',
        "guards": ["tests/test_audit6_fixes.py"],
        "why": "мёртвый info@ снова выглядел бы как живой ролевой",
    },
    {
        "id": "M15",
        "title": "«статус не трогать» снова уходит строкой «None» (прогон 27.09)",
        "path": "core/verdict_revision.py",
        "old": "        status = None if new_status is None else str(new_status)",
        "new": "        status = str(new_status)",
        "guards": ["tests/test_run7_fixes.py"],
        "why": "доказанно живые адреса снова выходили бы со статусом «None»",
    },
    {
        "id": "M16",
        "title": "загрузчик снова не берёт список из-за одного спорного имени (прогон 27.09)",
        "path": "core/github_parser.py",
        "old": "                if bad and len(bad) > ДОЛЯ_ОХРАНЫ_ПРЕДЕЛ * len(new_domains):",
        "new": "                if bad:",
        "guards": ["tests/test_run7_fixes.py"],
        "why": "обновления списков одноразовых снова не доходили бы до программы",
    },
    {
        "id": "M17",
        "title": "DNS снова ждёт мёртвый прокси шесть раз: нет второй дорожки (вариант В, 29.09)",
        "path": "core/dns_resolver.py",
        "old": "            if second is None and self._provider_excludes:",
        "new": "            if False:",
        "guards": ["tests/test_dns_proxy_switch.py"],
        "why": "вопрос через мёртвый прокси снова стоил бы 6×таймаут (90 с при 15 с) при живых рядом",
    },
    {
        "id": "M18",
        "title": "DNS забывает, какой прокси только что молчал (вариант В, 29.09)",
        "path": "core/dns_resolver.py",
        "old": "        if self._provider_excludes and proxy in self._recently_silent():",
        "new": "        if False:",
        "guards": ["tests/test_dns_proxy_switch.py"],
        "why": "каждый следующий вопрос домена снова платил бы таймаут за тот же мёртвый прокси",
    },
    {
        "id": "M19",
        "title": "прокси, отказавший и по DoH, и по обычному DNS, не меняется (вариант В, 29.09)",
        "path": "core/dns_resolver.py",
        "old": "    return silent or failed_kinds >= _BOTH_TRANSPORTS",
        "new": "    return silent",
        "guards": ["tests/test_dns_proxy_switch.py"],
        "why": "вопрос тратил бы попытки на «живой», но бесполезный прокси и терял ответ (живой замер 29.09)",
    },
    {
        "id": "M20",
        "title": "DoH через нераспознанную строку прокси уходит напрямую (вариант В, 29.09)",
        "path": "core/dns_resolver.py",
        "old": "        if not build_proxy_dict(proxy):\n            return None",
        "new": "        if False:\n            return None",
        "guards": ["tests/test_dns_proxy_switch.py"],
        "why": "вопрос с доменом базы ушёл бы в DoH с домашнего IP — утечка, ради которой DNS и заворачивали в прокси",
    },
    {
        "id": "M21",
        "title": "вторая DNS-дорожка принимает любой ответ, включая SERVFAIL и подменённое «нет» (29.09)",
        "path": "core/dns_resolver.py",
        "old": "    return kind == \"doh\" and response.rcode() in (dns.rcode.NXDOMAIN, dns.rcode.NOERROR)",
        "new": "    return True",
        "guards": ["tests/test_dns_proxy_switch.py"],
        "why": "перехваченное прокси «домена нет» по MX стало бы ложным «Мёртв», ранний SERVFAIL — «не проверено»",
    },
    {
        "id": "M22",
        "title": "резолвер Spamhaus снова спрашивает публичные DoH (29.09)",
        "path": "core/dns_checks.py",
        "old": "            proxy_provider=self._dns_proxy, public_doh=False)",
        "new": "            proxy_provider=self._dns_proxy)",
        "guards": ["tests/test_dns_proxy_switch.py"],
        "why": "отказ публичному резолверу (127.255.255.254) читался бы как «IP не в списке»",
    },
    {
        "id": "M23",
        "title": "DNS к частному адресу справочной уходит через чужой прокси (29.09)",
        "path": "core/dns_resolver.py",
        "old": "        if _is_local_address(nameserver):\n            return None",
        "new": "        if False:\n            return None",
        "guards": ["tests/test_dns_proxy_switch.py"],
        "why": "поиск Spamhaus стучался бы через бесплатный прокси в локальную сеть его хозяина",
    },
    {
        "id": "M24",
        "title": "два одинаковых «нет» через разные прокси снова не принимаются (29.09)",
        "path": "core/dns_resolver.py",
        "old": "                if heard_no is not None and heard_no[0] == no and heard_no[1] != proxy:",
        "new": "                if False:",
        "guards": ["tests/test_dns_proxy_switch.py"],
        "why": "настоящее «записи нет» терялось бы, когда DoH через прокси не работает (живой замер 29.09)",
    },
]


# --- восстановление исходников -------------------------------------------
#
# Реестр, а не try/finally по месту: прерывание с клавиатуры и падение
# интерпретатора обходят finally не всегда, а оставить в рабочей копии
# сломанный core/network.py нельзя ни при каких обстоятельствах.
_PENDING = {}


def _restore_all():
    for path, source in list(_PENDING.items()):
        try:
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(source)
        except Exception:
            print("!!! НЕ УДАЛОСЬ ВОССТАНОВИТЬ %s — проверь git diff" % path)
        _PENDING.pop(path, None)


atexit.register(_restore_all)


def _read(path):
    with open(path, "r", encoding="utf-8", newline="") as handle:
        return handle.read()


def _write(path, text):
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def _md5(path):
    with open(path, "rb") as handle:
        return hashlib.md5(handle.read()).hexdigest()


def _newline_of(source):
    """Какими переводами строк набран этот файл.

    В проекте есть и CRLF, и LF: `core/network.py` набран CRLF, а
    `core/dns_checks.py` — LF. Файлы читаются с newline="" (чтобы
    восстановление было побайтовым), поэтому якорь, написанный здесь через
    \\n, в CRLF-файле не находится вовсе — и гейт объявлял бы «код изменился»
    там, где не изменилось ничего.
    """
    crlf = source.count("\r\n")
    return "\r\n" if crlf and crlf >= (source.count("\n") - crlf) else "\n"


def _fit(fragment, source):
    """Приводит якорь к переводам строк того файла, в котором его ищут."""
    newline = _newline_of(source)
    plain = fragment.replace("\r\n", "\n")
    return plain if newline == "\n" else plain.replace("\n", newline)


# --- прогон тестов --------------------------------------------------------

def _pytest(args):
    """Возвращает (упало ли что-нибудь, последняя строка отчёта).

    `-x` останавливает на первом провале: нам нужен факт «заметили», а не
    полный список. На мутациях это разница между секундами и минутами.
    """
    command = [sys.executable, "-B", "-m", "pytest", "-q", "--no-header",
               "-x", "-p", "no:cacheprovider"] + args
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    output = (done.stdout or "") + (done.stderr or "")
    lines = [line for line in output.strip().splitlines() if line.strip()]
    tail = lines[-1] if lines else "нет вывода"
    # Ненулевой код возврата — это и провал теста, и ошибка сборки. Для нас
    # оба означают «набор отреагировал на поломку».
    return done.returncode != 0, tail


def _guard_args(mutation):
    return list(mutation["guards"])


# --- сам гейт -------------------------------------------------------------

def check_anchors():
    """Каждый якорь обязан находиться в коде РОВНО один раз."""
    problems = []
    for mutation in MUTATIONS:
        path = os.path.join(ROOT, mutation["path"].replace("/", os.sep))
        if not os.path.exists(path):
            problems.append("%s: нет файла %s" % (mutation["id"], mutation["path"]))
            continue
        source = _read(path)
        found = source.count(_fit(mutation["old"], source))
        if found == 0:
            problems.append("%s: якорь не найден в %s — код изменился, "
                            "мутацию надо переписать" % (mutation["id"], mutation["path"]))
        elif found > 1:
            problems.append("%s: якорь найден %d раза в %s — он неоднозначен"
                            % (mutation["id"], found, mutation["path"]))
    for mutation in MUTATIONS:
        for guard in mutation["guards"]:
            if not os.path.exists(os.path.join(ROOT, guard.replace("/", os.sep))):
                problems.append("%s: сторож %s не существует" % (mutation["id"], guard))
    return problems


def check_baseline(selected):
    """Набор обязан быть зелёным ДО поломок, иначе результаты ничего не значят."""
    files = sorted({guard for m in selected for guard in m["guards"]})
    failed, tail = _pytest(files)
    return (not failed), tail, len(files)


def run_mutation(mutation):
    """Возвращает ('caught'|'caught_elsewhere'|'survived', пояснение)."""
    path = os.path.join(ROOT, mutation["path"].replace("/", os.sep))
    source = _read(path)
    before = _md5(path)
    _PENDING[path] = source
    try:
        _write(path, source.replace(_fit(mutation["old"], source),
                                    _fit(mutation["new"], source), 1))
        if _md5(path) == before:
            return "survived", "мутация не изменила файл — замена совпала с исходником"
        caught, tail = _pytest(_guard_args(mutation))
        if caught:
            return "caught", tail
        # Сторожа промолчали. Прежде чем заявить дыру, спросим весь быстрый круг.
        caught_wide, tail_wide = _pytest(FAST_SUITE)
        if caught_wide:
            return "caught_elsewhere", tail_wide
        return "survived", tail_wide
    finally:
        _write(path, source)
        _PENDING.pop(path, None)
        if _md5(path) != before:
            raise SystemExit("!!! %s не восстановлен побайтово — останавливаюсь"
                             % mutation["path"])


def main(argv):
    wanted = [a for a in argv[1:] if not a.startswith("-")]
    if "--list" in argv:
        for mutation in MUTATIONS:
            print("%-4s %s" % (mutation["id"], mutation["title"]))
            print("       сторожа: %s" % ", ".join(mutation["guards"]))
        return 0

    selected = [m for m in MUTATIONS if not wanted or m["id"] in wanted]
    if not selected:
        print("не нашёл мутаций по имени: %s" % ", ".join(wanted))
        return 2

    print("=" * 78)
    print("МУТАЦИОННЫЙ ГЕЙТ: %d мутаций" % len(selected))
    print("=" * 78)

    problems = check_anchors()
    if problems:
        print("ОШИБКА: гейт сломан, а не код. Устаревший якорь или несуществующий")
        print("сторож означает, что мутация не применялась вовсе:")
        for problem in problems:
            print("   - %s" % problem)
        return 1

    ok, tail, count = check_baseline(selected)
    print("Базовый прогон сторожей (%d файлов): %s" % (count, tail))
    if not ok:
        print("ОШИБКА: набор красный ДО мутаций. Сначала починить тесты — "
              "на красном наборе мутационный гейт не значит ничего.")
        return 1
    print()

    survived, elsewhere = [], []
    for mutation in selected:
        verdict, tail = run_mutation(mutation)
        if verdict == "caught":
            mark = "ПОЙМАНО"
        elif verdict == "caught_elsewhere":
            mark = "поймано, но не сторожем"
            elsewhere.append(mutation)
        else:
            mark = "НЕ ЗАМЕЧЕНО"
            survived.append(mutation)
        print("[%-22s] %-4s %s" % (mark, mutation["id"], mutation["title"]))
        print("%26s %s" % ("", tail))

    print()
    print("=" * 78)
    print("поймано: %d из %d" % (len(selected) - len(survived), len(selected)))

    if elsewhere:
        print()
        print("Сторож указан неверно (мутацию поймал другой тест) — поправь список:")
        for mutation in elsewhere:
            print("   - %s: %s" % (mutation["id"], ", ".join(mutation["guards"])))

    if survived:
        print()
        print("ДЫРА В НАБОРЕ. Эти поломки не заметил НИ ОДИН тест быстрого круга:")
        for mutation in survived:
            print("   - %s %s" % (mutation["id"], mutation["title"]))
            print("        цена ошибки: %s" % mutation["why"])
            print("        где: %s" % mutation["path"])
        print()
        print("Это не повод отключить гейт. Это список тестов, которых не хватает.")
        return 1

    print(SUCCESS_TOKEN)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
