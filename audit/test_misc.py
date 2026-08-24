# -*- coding: utf-8 -*-
"""ФАЗА 3+4: S2.3 WHOIS/RDAP, S2.6 сайт, S2.7 парковка, S4.5 role, S4.6 имя/пол/страна,
S4.4 поведение при сбое автообновления, S3.6 структура greylisting-повтора."""
import sys, os, time, ast, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')
from core.pipeline import ValidationPipeline
from core.heuristics import is_parked_domain, PARKING_HOSTS
from core.parser.name_extractor import NameExtractor
from core.parser.ml_predictor import MLPredictor
from core.provider import classify_domain
from core.disposable import is_disposable

p = ValidationPipeline({'on_log': lambda *a: None})

print("=" * 90)
print("S2.3 ВОЗРАСТ ДОМЕНА: WHOIS + RDAP-фоллбэк + кэш")
print("=" * 90)
for d in ["github.com", "gmail.com", "google.com", "yandex.ru", "mail.ru",
          "tesla.com", "nonexistent-zzq7x4m2nv8w1k.com"]:
    t0 = time.time()
    age = p._get_domain_age_days(d)
    dt = time.time() - t0
    t1 = time.time()
    age2 = p._get_domain_age_days(d)
    dt2 = time.time() - t1
    years = ("%.1f лет" % (age / 365.25)) if age > 0 else "НЕ ОПРЕДЕЛЁН"
    print("   %-34s age=%-7d %-14s %5.1fs | кэш: %5.3fs %s"
          % (d, age, years, dt, dt2, "OK" if dt2 < 0.01 else "КЭШ НЕ РАБОТАЕТ"))
print("   Отдельно RDAP-фоллбэк (rdap.org) — работает ли сам по себе:")
import urllib.request, json, datetime
for d in ["github.com", "gmail.com"]:
    try:
        req = urllib.request.Request("https://rdap.org/domain/%s" % d, method="GET")
        req.add_header("User-Agent", "Mozilla/5.0")
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode())
        ev = [e for e in data.get("events", []) if e.get("eventAction") == "registration"]
        print("     rdap.org/%s -> registration=%s" % (d, ev[0]["eventDate"] if ev else "НЕТ СОБЫТИЯ"))
    except Exception as e:
        print("     rdap.org/%s -> ОШИБКА %s: %s" % (d, type(e).__name__, str(e)[:60]))

print()
print("=" * 90)
print("S2.6 ЖИВОЙ САЙТ (HEAD) + кэш")
print("=" * 90)
for d in ["github.com", "gmail.com", "nonexistent-zzq7x4m2nv8w1k.com", "example.com"]:
    t0 = time.time(); a = p._check_http_alive(d); dt = time.time() - t0
    t1 = time.time(); p._check_http_alive(d); dt2 = time.time() - t1
    print("   %-34s alive=%-6s %5.1fs | кэш %5.3fs" % (d, a, dt, dt2))

print()
print("=" * 90)
print("S2.7 ПРИПАРКОВАННЫЙ ДОМЕН")
print("=" * 90)
print("   Список PARKING_HOSTS (%d записей): %s" % (len(PARKING_HOSTS), ", ".join(PARKING_HOSTS)))
for mx, exp in [("mx.sedoparking.com", True), ("mail.bodis.com", True),
                ("park-mx.afternic.com", True), ("mx1.parkingcrew.net", True),
                ("gmail-smtp-in.l.google.com", False), ("", False), ("N/A", False),
                ("mx.hugedomains.com", True), ("mail.dan.com", True)]:
    got = is_parked_domain(mx)
    print("   [%s] is_parked_domain(%-30s) = %s" % ("OK " if got == exp else "РАСХ", mx, got))
print("   Заявлено 'MX на sedoparking, bodis, afternic и т.п.' -> все три присутствуют")
print("   ВАЖНО: проверяется ТОЛЬКО primary MX (res['mx_record']), A-запись не проверяется")

print()
print("=" * 90)
print("S4.5 ROLE-BASED")
print("=" * 90)
src = open("core/pipeline.py", encoding="utf-8").read()
blk = src[src.index("roles = {"):]
blk = blk[:blk.index("}") + 1]
roles = ast.literal_eval(blk[blk.index("{"):])
print("   Записей в списке: %d (заявлено 40+)" % len(roles))
print("   ", ", ".join(sorted(roles)))
print("   Сравнение: local_part.lower() in roles -> ТОЧНОЕ РАВЕНСТВО")
for a, exp in [("info@corp.com", True), ("noreply@corp.com", True), ("admin@corp.com", True),
               ("no-reply@corp.com", True), ("sales-team@corp.com", False),
               ("info.desk@corp.com", False), ("noreply2@corp.com", False),
               ("Info@corp.com", True), ("mailer-daemon@corp.com", False),
               ("do-not-reply@corp.com", False), ("newsletter@corp.com", False),
               ("careers@corp.com", False), ("team@corp.com", False)]:
    lp = a.split("@")[0].lower()
    got = lp in roles
    mark = "OK " if got == exp else "РАСХ"
    note = ""
    if not got and exp is False and lp in ("sales-team", "info.desk", "noreply2",
                                           "mailer-daemon", "do-not-reply", "newsletter",
                                           "careers", "team"):
        note = "  <-- ролевой по смыслу, но НЕ ловится (нет паттернов/префиксов)"
    print("   [%s] %-26s -> %s%s" % (mark, a, got, note))

print()
print("=" * 90)
print("S4.6 ИМЯ / ПОЛ / СТРАНА")
print("=" * 90)
ne = NameExtractor(enable_osint=False)
mp = MLPredictor(enable_ml=False)
for a in ["john.doe@gmail.com", "ivan.petrov@mail.ru", "anna_smith@corp.com",
          "postmaster@gmail.com", "jsmith@corp.com", "maria.garcia@empresa.es",
          "xk3n9fj2q1x@gmail.com"]:
    name = ne.extract_name(a)
    g, c = mp.predict(name, email=a)
    print("   %-30s name='%s'  gender='%s'  country='%s'" % (a, name, g, c))
print("   Помечены ли поля как предположительные? Ищем в ui/gui.py признак:")
gui = open("ui/gui.py", encoding="utf-8").read()
for kw in ["предпол", "guess", "~", "probable", "(?)"]:
    print("     '%s' встречается в gui.py: %d раз" % (kw, gui.count(kw)))

print()
print("=" * 90)
print("S4.4 ЧТО ПРОИСХОДИТ ПРИ СБОЕ АВТООБНОВЛЕНИЯ")
print("=" * 90)
from core.github_parser import BlacklistDownloader
import shutil, tempfile
tmp = tempfile.mkdtemp()
shutil.copy("data/disposable.txt", os.path.join(tmp, "disposable.txt"))
shutil.copy("data/disposable_extra.txt", os.path.join(tmp, "disposable_extra.txt"))
before = os.path.getsize(os.path.join(tmp, "disposable.txt"))
bd = BlacklistDownloader(data_dir=tmp)
bd.sources = {"disposable.txt": "https://raw.githubusercontent.com/does-not-exist-zzq/x/master/y.txt",
              "disposable_extra.txt": "https://127.0.0.1:1/nothing"}
rep = bd.download_all()
after = os.path.getsize(os.path.join(tmp, "disposable.txt"))
print("   URL битые. Отчёт: %s" % rep)
print("   размер файла до=%d после=%d  [%s]"
      % (before, after, "СПИСОК СОХРАНЁН" if before == after else "СПИСОК ПОВРЕЖДЁН"))
bd2 = BlacklistDownloader(data_dir=tmp)
bd2.sources = {"disposable.txt": "https://raw.githubusercontent.com/torvalds/linux/master/README"}
rep2 = bd2.download_all()
after2 = os.path.getsize(os.path.join(tmp, "disposable.txt"))
print("   Ответ 200, но содержимое не список доменов: %s" % rep2)
print("   размер файла после=%d  [%s]"
      % (after2, "СПИСОК СОХРАНЁН (сработал предохранитель)" if after2 == before else "СПИСОК ЗАТЁРТ"))
print("   Атомарность записи: os.replace(tmp_path, filepath) — атомарная подмена, "
      "полупустой файл при обрыве невозможен")
print("   ОДНАКО: обновляется только data/*.txt (SpamFilter). "
      "Множество DISPOSABLE_DOMAINS в core/disposable.py (%d доменов) захардкожено "
      "и автообновлением НЕ затрагивается." % len(__import__("core.disposable", fromlist=["x"]).DISPOSABLE_DOMAINS))
shutil.rmtree(tmp, ignore_errors=True)

print()
print("=" * 90)
print("S3.6 GREYLISTING — структура повтора")
print("=" * 90)
ps = open("core/pipeline.py", encoding="utf-8").read()
i = ps.index("=== Greylisting Auto-Retry")
seg = ps[i - 400:i + 1400]
for ln in seg.splitlines():
    if any(k in ln for k in ("greylisted_queue", "range(90)", "time.sleep", "while not",
                             "worker_threads", "join()", "is_running", "retry_count")):
        print("     ", ln.strip())
print()
print("   ФАКТЫ ИЗ КОДА:")
print("     1. Повтор стартует ПОСЛЕ join() всех воркеров — то есть весь прогон стоит.")
print("     2. Ожидание: for i in range(90): time.sleep(1) — блокирует поток пайплайна на 90 с.")
print("     3. Повтор идёт в ОДИН поток (while not greylisted_queue.empty()), без ThreadPool.")
print("     4. Greylisted-адреса НЕ отдаются в on_result на первом проходе (return),")
print("        значит до конца повтора их в выдаче нет вообще.")
print("     5. Если is_running стало False во время ожидания или повтора —")
print("        очередь отбрасывается, и эти адреса НЕ попадут в результат НИКОГДА.")
