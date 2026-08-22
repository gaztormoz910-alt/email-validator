# -*- coding: utf-8 -*-
"""ФАЗА 0 (мёртвый код) + ФАЗА 5 (качество тестов)."""
import sys, os, re, ast
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
sys.stdout.reconfigure(encoding='utf-8')

print("=" * 96)
print("ФАЗА 5.2/5.3 — КАЧЕСТВО СУЩЕСТВУЮЩИХ ТЕСТОВ")
print("=" * 96)

WEAK = {"assertIsNotNone", "assertIsInstance", "assertIn", "assertGreater",
        "assertTrue", "assertFalse", "assertIsNone"}
SUBJECT_CALLS = re.compile(r"\b(check_email|check_dnsbl|check_ptr|check_fcrdns|"
                           r"_parse_smtp_response|calculate_engagement_score|normalize_for_dedup|"
                           r"looks_machine_generated|is_parked_domain|is_disposable|_parse_proxy|"
                           r"classify_domain|_pick_best_proxy|_update_proxy_score|_do_single_ping|"
                           r"stealth_smtp_ping|has_gravatar|extract|run_async_checker|"
                           r"check_single_proxy|validate_email_syntax|clean_email|split_proxies)")

smoke = []
total = 0
for fn in sorted(os.listdir("tests")):
    if not fn.endswith(".py"):
        continue
    path = os.path.join("tests", fn)
    tree = ast.parse(open(path, encoding="utf-8-sig").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            total += 1
            body = ast.get_source_segment(open(path, encoding="utf-8-sig").read(), node) or ""
            calls_subject = bool(SUBJECT_CALLS.search(body))
            asserts = re.findall(r"self\.(assert\w+)", body)
            n_lines = len([l for l in body.splitlines() if l.strip()
                           and not l.strip().startswith(("#", '"""'))])
            if not calls_subject:
                smoke.append((path, node.name, len(asserts), n_lines,
                              "не вызывает ни одной проверяемой функции"))
            elif len(asserts) <= 1 and n_lines <= 5:
                smoke.append((path, node.name, len(asserts), n_lines, "1 assert, тело <=5 строк"))

print("  Всего тестовых функций: %d" % total)
print("  Тестов без обращения к проверяемой логике (smoke/структурные): %d" % len(smoke))
for p, n, a, l, why in smoke:
    print("     %-28s %-46s assert=%d строк=%d  %s" % (p, n, a, l, why))

print()
print("  ТАВТОЛОГИЧЕСКИЕ (тест сам подставляет ответ, который потом проверяет):")
for fn in sorted(os.listdir("tests")):
    if not fn.endswith(".py"):
        continue
    path = os.path.join("tests", fn)
    src = open(path, encoding="utf-8-sig").read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            body = ast.get_source_segment(src, node) or ""
            if re.search(r"_cache\[[^\]]+\]\s*=", body):
                print("     %-24s %-46s — подменяет кэш и проверяет его же" % (path, node.name))

print()
print("=" * 96)
print("ФАЗА 0.2 — ЧЕГО В СПЕЦИФИКАЦИИ НЕТ, А В КОДЕ ЕСТЬ / НЕДОДЕЛКИ")
print("=" * 96)
pats = [("TODO/FIXME/HACK", re.compile(r"#\s*(TODO|FIXME|HACK|XXX)", re.I)),
        ("except: pass (голый)", re.compile(r"except\s*:\s*\n\s*pass")),
        ("except Exception: pass", re.compile(r"except Exception[^\n]*:\s*\n\s*pass")),
        ("except -> return None", re.compile(r"except[^\n]*:\s*\n\s*return None")),
        ("return True  # temp", re.compile(r"return (True|False)\s*#")),
        ]
files = []
for d, _, fs in os.walk("."):
    if any(x in d for x in (".git", "__pycache__", "tor_bin", "audit", ".pytest_cache")):
        continue
    for f in fs:
        if f.endswith(".py"):
            files.append(os.path.join(d, f))

for label, rx in pats:
    hits = []
    for f in files:
        src = open(f, encoding="utf-8", errors="ignore").read()
        for m in rx.finditer(src):
            line = src[:m.start()].count("\n") + 1
            hits.append("%s:%d" % (f.replace("\\", "/"), line))
    print("  %-26s %3d  %s" % (label, len(hits), ", ".join(hits[:12]) + (" ..." if len(hits) > 12 else "")))

print()
print("  Корневые test_*.py (побочные эффекты при импорте, ломают голый `pytest`):")
for f in sorted(os.listdir(".")):
    if f.startswith("test_") and f.endswith(".py"):
        raw = open(f, "rb").read()
        nul = b"\x00" in raw
        src = raw.decode("utf-8", "ignore")
        has_test_fn = bool(re.search(r"^def test_", src, re.M))
        net = bool(re.search(r"requests\.|urlopen|session\.get|socket", src))
        writes = bool(re.search(r"open\([^)]*['\"]w", src))
        print("     %-20s null-байты=%-5s функций test_=%-5s сеть=%-5s пишет файлы=%s"
              % (f, nul, has_test_fn, net, writes))

print()
print("  Неиспользуемые модули (импортируются ли откуда-нибудь):")
mods = ["core/ai_filter.py", "core/tor_manager.py", "core/streamer.py", "core/osint.py",
        "async_proxy_checker.py", "original_engine.py", "core/parser/osint.py",
        "core/ai_engine.py", "core/gravatar.py", "core/github_parser.py"]
allsrc = "\n".join(open(f, encoding="utf-8", errors="ignore").read() for f in files)
for m in mods:
    if not os.path.exists(m):
        continue
    name = os.path.basename(m)[:-3]
    used = len(re.findall(r"(?:from|import)\s+[\w.]*\b%s\b" % re.escape(name), allsrc))
    print("     %-28s импортируется %d раз %s" % (m, used, "<-- НИКЕМ" if used == 0 else ""))
