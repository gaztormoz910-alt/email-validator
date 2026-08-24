# -*- coding: utf-8 -*-
"""Фаза 2: пересчёт всех количественных заявлений спецификации."""
import sys, os, re, ast, io
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')

print("="*70)
print("ФАЗА 2. ПЕРЕСЧЁТ ЧИСЛОВЫХ ЗАЯВЛЕНИЙ")
print("="*70)

# --- S1.2: словарь опечаток ---
from core.cleaner import EmailCleaner
c = EmailCleaner()
tm = c._typo_map
print(f"\n[S1.2] Заявлено ~70 замен опечаток")
print(f"       РЕАЛЬНО в _typo_map: {len(tm)} записей")
print(f"       уникальных ЦЕЛЕЙ (правильных доменов): {len(set(tm.values()))}")
# сколько ключей дублируются
dups = [k for k in tm if list(tm.keys()).count(k) > 1]
print(f"       дублей ключей: {len(dups)}")
# сколько целей отсутствует в popular_domains (значит очистка хвостов их не увидит)
missing = sorted(set(tm.values()) - set(c.popular_domains))
print(f"       целей НЕ входящих в GLOBAL_VERIFIED_DOMAINS: {len(missing)} -> {missing}")

# --- S2.5: DNSBL зоны ---
from core.network import DNSBL_ZONES
print(f"\n[S2.5] Заявлено 6 DNSBL")
print(f"       РЕАЛЬНО в DNSBL_ZONES: {len(DNSBL_ZONES)} -> {DNSBL_ZONES}")

# --- S3.3: SMTP коды ---
src = open('core/network.py', encoding='utf-8').read()
fn = src[src.index('def _parse_smtp_response'):src.index('def _do_single_ping')]
codes = set()
for m in re.finditer(r'code\s*==\s*(\d{3})', fn):
    codes.add(int(m.group(1)))
for m in re.finditer(r'code in \(([^)]*)\)', fn):
    for x in re.findall(r'\d{3}', m.group(1)):
        codes.add(int(x))
branches = len(re.findall(r'return make_result', fn))
print(f"\n[S3.3] Заявлено 20+ сценариев классификации")
print(f"       Явно перечисленных SMTP-кодов: {len(codes)} -> {sorted(codes)}")
print(f"       Всего веток return make_result(...): {branches}")

# --- S4.4: disposable ---
from core.disposable import DISPOSABLE_DOMAINS, get_disposable_count
print(f"\n[S4.4] Заявлено 8948 disposable-доменов")
print(f"       Python-set DISPOSABLE_DOMAINS (используется is_disposable): {get_disposable_count()}")
for f in ('data/disposable.txt','data/disposable_extra.txt'):
    n = sum(1 for l in open(f, encoding='utf-8') if l.strip())
    print(f"       {f}: {n} непустых строк")
from core.filters import SpamFilter
sf = SpamFilter()
print(f"       SpamFilter.blacklist_domains (объединение файлов): {sf.get_count()}")
union = set(DISPOSABLE_DOMAINS) | sf.blacklist_domains
print(f"       ОБЪЕДИНЕНИЕ всех источников: {len(union)}")

# --- S4.5: role-based ---
psrc = open('core/pipeline.py', encoding='utf-8').read()
block = psrc[psrc.index('roles = {'):]
block = block[:block.index('}')+1]
roles = ast.literal_eval(block[block.index('{'):])
print(f"\n[S4.5] Заявлено 40+ role-паттернов")
print(f"       РЕАЛЬНО в множестве roles: {len(roles)}")
print(f"       Тип сравнения: точное равенство local_part -> НЕ паттерны (нет wildcard/regex)")

# --- S5.4: сигналы скоринга ---
ssrc = open('core/scoring.py', encoding='utf-8').read()
appends = re.findall(r'signals\.append\("([^"]+)"\)', ssrc)
print(f"\n[S5.4] Заявлено ровно 23 сигнала")
print(f"       Веток signals.append(...) в calculate_engagement_score: {len(appends)}")
for i,a in enumerate(appends,1):
    print(f"         {i:2d}. {a}")
pos = [a for a in appends if a.startswith('+')]
neg = [a for a in appends if a.startswith('-')]
print(f"       Плюсовых веток: {len(pos)}  Минусовых веток: {len(neg)}  Прочих: {len(appends)-len(pos)-len(neg)}")
print(f"       Уникальных ВХОДНЫХ параметров, влияющих на балл: см. сигнатуру функции")
import inspect
from core.scoring import calculate_engagement_score as ces
params = list(inspect.signature(ces).parameters)
print(f"       Параметров функции: {len(params)} -> {params}")

# --- S5.1/S5.2 суммы ---
def num(s):
    m = re.match(r'([+-]\d+):', s)
    return int(m.group(1)) if m else 0
print(f"\n[S5.1/S5.2] Сумма всех плюсов (если бы сработали все): {sum(num(a) for a in pos)}")
print(f"            Сумма всех минусов: {sum(num(a) for a in neg)}")
print(f"            Взаимоисключающие ветки есть (elif), поэтому реальный максимум ниже")
