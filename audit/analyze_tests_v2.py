# -*- coding: utf-8 -*-
"""ФАЗА 5 (уточнённая): качество тестов с учётом алиасов (self.parse/self.score).

Первая версия эвристики дала массовые ложные срабатывания: тесты вызывают
проверяемые функции через алиасы, заданные в setUp. Здесь алиасы разрешаются.
"""
import sys, os, re, ast
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
sys.stdout.reconfigure(encoding='utf-8')

SUBJECTS = ("check_email", "check_dnsbl", "check_ptr", "check_fcrdns", "_parse_smtp_response",
            "calculate_engagement_score", "normalize_for_dedup", "looks_machine_generated",
            "is_parked_domain", "is_disposable", "_parse_proxy", "classify_domain",
            "_pick_best_proxy", "_update_proxy_score", "_do_single_ping", "stealth_smtp_ping",
            "has_gravatar", "run_async_checker", "check_single_proxy", "validate_email_syntax",
            "clean_email", "split_proxies_by_fcrdns", "local_part_entropy", "extract",
            "_proxy_scheme", "SocksSMTP", "mark_dead", "get_proxy", "all_proxies_dead",
            "has_ptr_proxies", "_get_mx_semaphore", "_record_mx_error", "set_ptr_proxies")

weak = []
zero_assert = []
tautological = []
total = 0

for fn in sorted(os.listdir("tests")):
    if not fn.endswith(".py"):
        continue
    path = os.path.join("tests", fn)
    src = open(path, encoding="utf-8-sig").read()
    tree = ast.parse(src)
    for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
        # алиасы: self.X = <subject>  либо  def X(self,...): return <subject>(...)
        cls_src = ast.get_source_segment(src, cls) or ""
        aliases = set()
        for m in re.finditer(r"self\.(\w+)\s*=\s*(\w+)\s*$", cls_src, re.M):
            if m.group(2) in SUBJECTS:
                aliases.add(m.group(1))
        for m in re.finditer(r"def (\w+)\(self[^)]*\):\s*\n\s*return ([\w.]+)", cls_src):
            tgt = m.group(2).split(".")[-1]
            if tgt in SUBJECTS:
                aliases.add(m.group(1))
        names = set(SUBJECTS) | aliases
        rx = re.compile(r"\b(%s)\s*\(" % "|".join(re.escape(n) for n in names))
        for node in cls.body:
            if not (isinstance(node, ast.FunctionDef) and node.name.startswith("test_")):
                continue
            total += 1
            body = ast.get_source_segment(src, node) or ""
            n_assert = len(re.findall(r"self\.assert", body))
            calls = bool(rx.search(body))
            if n_assert == 0:
                zero_assert.append((path, node.name))
            if re.search(r"_cache\[[^\]]+\]\s*=", body):
                tautological.append((path, node.name, "подставляет значение в кэш и его же проверяет"))
            if not calls and n_assert > 0:
                weak.append((path, node.name, n_assert,
                             "не вызывает ни одной проверяемой функции — проверяет только константы/структуру"))

print("=" * 96)
print("ФАЗА 5 (уточнённо). КАЧЕСТВО НАБОРА tests/ — с разрешением алиасов setUp")
print("=" * 96)
print("  Всего тестов: %d" % total)
print()
print("  A. Тесты без единого assert (проверяют только 'не упало'): %d" % len(zero_assert))
for p, n in zero_assert:
    print("       %-26s %s" % (p, n))
print()
print("  B. Тавтологические (сами подставляют ответ): %d" % len(tautological))
for p, n, w in tautological:
    print("       %-26s %-42s %s" % (p, n, w))
print()
print("  C. Не обращаются к логике вообще (структура/константы): %d" % len(weak))
for p, n, a, w in weak:
    print("       %-26s %-42s assert=%d  %s" % (p, n, a, w))
print()
print("  ИТОГО слабых: %d из %d (%.0f%%). Остальные %d вызывают настоящие функции."
      % (len(zero_assert) + len(tautological) + len(weak), total,
         (len(zero_assert) + len(tautological) + len(weak)) * 100.0 / total,
         total - len(zero_assert) - len(tautological) - len(weak)))

print()
print("=" * 96)
print("ЗАПАС ПРОЧНОСТИ ASSERT'ОВ В СКОРИНГЕ (насколько балл может упасть незамеченным)")
print("=" * 96)
sys.path.insert(0, ROOT)
from core.scoring import calculate_engagement_score as S
CHECKS = [
    ("test_valid_smtp_with_good_server", dict(email='test@corp.com', smtp_status='Valid',
                                              has_ptr=True, has_starttls=True), ">= 30"),
    ("test_full_inbox_with_good_server", dict(email='test@corp.com', smtp_status='Valid',
                                              smtp_reason='452 OK (Mailbox Full)',
                                              has_ptr=True, has_starttls=True), ">= 40"),
]
for name, kw, bound in CHECKS:
    r = S(**kw)
    b = int(bound.split()[-1])
    print("   %-36s фактический балл=%-4d граница теста %s -> запас %d баллов (%.0f%%)"
          % (name, r["score"], bound, r["score"] - b, (r["score"] - b) * 100.0 / max(r["score"], 1)))
print("   => такие широкие границы пропустят крупную регрессию скоринга.")
