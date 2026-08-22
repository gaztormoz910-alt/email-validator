# -*- coding: utf-8 -*-
"""ФАЗА 3+4: Этап 1 — S1.1 синтаксис, S1.2 опечатки, S1.3 хвосты, S1.4 дедуп."""
import sys, os, subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')
from core.network import validate_email_syntax as V
from core.cleaner import EmailCleaner, normalize_for_dedup as N

print("="*80); print("S1.1 RFC 5322"); print("="*80)
CASES = [
 # (адрес, ожидание, комментарий)
 ("john.doe@gmail.com", True, "обычный"),
 ("a@b.co", True, "минимальный"),
 ("john..doe@gmail.com", False, "двойная точка"),
 ("john.@gmail.com", False, "точка перед @"),
 ("john@.gmail.com", False, "точка после @"),
 ("jo hn@gmail.com", False, "пробел"),
 ("john@gmail@com", False, "два @"),
 ("john@gmail", False, "нет TLD"),
 ("@gmail.com", False, "нет локальной части"),
 ("john@", False, "нет домена"),
 ("a"*310+"@gmail.com", False, "длина > 320"),
 (".john@gmail.com", False, "точка в начале"),
 ("john+tag@gmail.com", True, "плюс-тег валиден по RFC"),
 ("john_doe-1@sub.example.co.uk", True, "поддомен + составной TLD"),
 ("JOHN@GMAIL.COM", True, "верхний регистр"),
 ("john@gmail.com.", False, "точка в конце домена"),
 ('"john doe"@gmail.com', False, "quoted-string (RFC разрешает, строгая регулярка — нет)"),
 ("john@[192.168.1.1]", False, "IP-литерал (RFC разрешает)"),
 ("иван@почта.рф", False, "IDN/юникод (не преобразуется в punycode перед проверкой)"),
]
bad = 0
for a,exp,note in CASES:
    got = V(a)
    ok = got == exp
    if not ok: bad += 1
    disp = a if len(a) < 40 else a[:20]+"...("+str(len(a))+")"
    print(f"  [{'OK ' if ok else 'РАСХ'}] {disp:<34} -> {got!s:<6} ожидалось {exp!s:<6} {note}")
print(f"  Расхождений с ожиданием: {bad} (последние 3 — сознательное сужение RFC, см. отчёт)")

print("\n  Длина локальной части: RFC максимум 64")
long_local = "a"*70 + "@gmail.com"
print(f"    70 символов в local -> {V(long_local)}  (регулярка допускает 1+63=64, значит должно быть False)")
print(f"    len(email)={len(long_local)}")

print("\n"+"="*80); print("S1.2 ОПЕЧАТКИ + S1.3 ХВОСТЫ"); print("="*80)
c = EmailCleaner()
T = [
 ("bob@gamil.com","bob@gmail.com","опечатка из спецификации"),
 ("bob@yandex.r","bob@yandex.ru","опечатка из спецификации"),
 ("bob@gmail.comtelefoon","bob@gmail.com","мусорный хвост из спецификации"),
 ("bob@gmail.com.br.spam.xyz","bob@gmail.com","вложенные поддомены"),
 ("bob@gmail.com-jobs","bob@gmail.com","хвост через дефис"),
 ("karl....motiv@gmail.com","karl.motiv@gmail.com","повторяющиеся точки"),
 (".karl.motiv.@gmail.com","karl.motiv@gmail.com","точки по краям"),
 ("bob@gmail.com.","bob@gmail.com","точка в конце"),
 ("bob@yandex.rublahblah",None,"хвост у домена, которого НЕТ в popular_domains"),
 ("bob@mail.ruslan-company.com",None,"легитимный домен, начинающийся как известный"),
 ("bob@tesla.com","bob@tesla.com","корпоративный — не трогать"),
 ("bob@sberbank.ru","bob@sberbank.ru","корпоративный — не трогать"),
]
for src, exp, note in T:
    got = c.clean_email(src)
    mark = "OK " if (exp is None or got == exp) else "РАСХ"
    print(f"  [{mark}] {src:<34} -> {got}   ({note})")

print("\n  Недетерминированность: домен с >3 точками ищет совпадение перебором МНОЖЕСТВА")
outs = set()
for i in range(12):
    r = subprocess.run([sys.executable, "-c",
        "import sys;sys.path.insert(0,r'%s');from core.cleaner import EmailCleaner;"
        "print(EmailCleaner().clean_email('bob@yahoo.co.uk.live.co.uk.spam.xyz'))"
        % os.path.dirname(os.path.dirname(os.path.abspath(__file__)))],
        capture_output=True, text=True)
    outs.add(r.stdout.strip())
print(f"    12 запусков в разных процессах (PYTHONHASHSEED разный) -> различных результатов: {len(outs)}")
for o in sorted(outs): print(f"       {o}")

print("\n"+"="*80); print("S1.4 НОРМАЛИЗАЦИЯ ДЛЯ ДЕДУПА"); print("="*80)
D = [
 ("john.doe@gmail.com","johndoe@gmail.com",True),
 ("john+news@gmail.com","john@gmail.com",True),
 ("j@googlemail.com","j@gmail.com",True),
 ("John.Doe+x@GMail.com","johndoe@gmail.com",True),
 ("john.doe@yandex.ru","johndoe@yandex.ru",False),
 ("john+tag@corp.com","john@corp.com",False),
 ("john.doe@outlook.com","johndoe@outlook.com",False),
]
for a,b,same in D:
    na, nb = N(a), N(b)
    got = (na == nb)
    print(f"  [{'OK ' if got==same else 'РАСХ'}] {a:<26} ~ {b:<22} -> {na} / {nb}  склеены={got} ожидалось={same}")
