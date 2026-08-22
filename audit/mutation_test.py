# -*- coding: utf-8 -*-
"""ФАЗА 5: мутационное тестирование существующего набора tests/ (G1).

Ломаем по одному ключевому месту, гоняем ВЕСЬ набор, возвращаем файл байт в байт.
Если после поломки набор остаётся зелёным — он это место не проверяет.
"""
import sys, os, subprocess, hashlib, shutil, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
sys.stdout.reconfigure(encoding='utf-8')

MUTATIONS = [
    ("M1 синтаксис: убрать запрет двойных точек/пробелов",
     "core/network.py",
     "    if _BAD_SYNTAX_PATTERNS.search(email):\n        return False",
     "    if _BAD_SYNTAX_PATTERNS.search(email):\n        pass"),

    ("M2 скоринг: перевернуть знак у SMTP 250 OK (+55 -> -55)",
     "core/scoring.py",
     "            score += 55\n",
     "            score -= 55\n"),

    ("M3 DNSBL: всегда 'в чёрном списке'",
     "core/network.py",
     "        result = False\n        try:\n            ip = str(self.resolver.resolve(mx_host, 'A')[0])",
     "        result = True\n        try:\n            ip = str(self.resolver.resolve(mx_host, 'A')[0])"),

    ("M4 эвристика: всякий адрес — машинный",
     "core/heuristics.py",
     "    return suspicious >= 2",
     "    return True"),

    ("M5 дедуп: нормализация ничего не склеивает",
     "core/cleaner.py",
     '    email = email.strip().lower()\n    local, domain = email.rsplit("@", 1)',
     '    return email\n    local, domain = email.rsplit("@", 1)'),

    ("M6 SMTP: '550 User Does Not Exist' -> считать ящик живым",
     "core/network.py",
     '                return make_result("invalid", "550 User Does Not Exist")',
     '                return make_result("valid", "550 User Does Not Exist")'),

    ("M7 бан прокси: снять порог, никогда не банить",
     "core/network.py",
     "                if self._proxy_consecutive_fails[proxy] >= PROXY_MAX_CONSECUTIVE_FAILS:\n                    self._proxy_banned.add(proxy)",
     "                if False:\n                    self._proxy_banned.add(proxy)"),

    ("M8 защита от утечки IP: разрешить прямое соединение",
     "core/network.py",
     '        if proxy is None and self.has_proxies_configured():\n            return {"status": "unknown", "reason": "All Proxies Dead (прямое соединение запрещено)"}',
     '        if False:\n            return {"status": "unknown", "reason": "All Proxies Dead (прямое соединение запрещено)"}'),
]


def run_suite():
    p = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q", "--no-header", "-p", "no:cacheprovider"],
                       capture_output=True, text=True)
    tail = [l for l in p.stdout.strip().splitlines() if l.strip()][-1] if p.stdout.strip() else "?"
    failed = len(re.findall(r"^FAILED", p.stdout, re.M))
    m = re.search(r"(\d+) failed", p.stdout)
    if m:
        failed = int(m.group(1))
    return failed, tail


def md5(path):
    return hashlib.md5(open(path, "rb").read()).hexdigest()


print("=" * 92)
print("ФАЗА 5. МУТАЦИОННОЕ ТЕСТИРОВАНИЕ НАБОРА tests/")
print("=" * 92)
base_failed, base_tail = run_suite()
print("  Базовый прогон (код не тронут): %s" % base_tail)
print()

results = []
for name, path, old, new in MUTATIONS:
    src = open(path, encoding="utf-8", newline="").read()
    before = md5(path)
    if old not in src:
        print("  [ПРОПУСК] %s — якорь не найден в %s" % (name, path))
        results.append((name, None, "якорь не найден"))
        continue
    try:
        open(path, "w", encoding="utf-8", newline="").write(src.replace(old, new, 1))
        failed, tail = run_suite()
    finally:
        open(path, "w", encoding="utf-8", newline="").write(src)
        assert md5(path) == before, "ФАЙЛ %s НЕ ВОССТАНОВЛЕН!" % path
    caught = failed > base_failed
    results.append((name, failed, tail))
    print("  [%s] %s" % ("ПОЙМАНО " if caught else "НЕ ЗАМЕЧЕНО", name))
    print("             упало тестов: %-4d | %s" % (failed, tail))

print()
print("=" * 92)
caught = sum(1 for _, f, _ in results if isinstance(f, int) and f > base_failed)
total = sum(1 for _, f, _ in results if isinstance(f, int))
print("  ПОЙМАНО МУТАЦИЙ: %d из %d" % (caught, total))
print("  НЕ ЗАМЕЧЕНО:")
for n, f, t in results:
    if isinstance(f, int) and f <= base_failed:
        print("     - %s" % n)
print()
print("  Контроль целостности: все файлы восстановлены побайтово (md5 сверен).")
