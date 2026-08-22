# -*- coding: utf-8 -*-
"""ФАЗА 4: S4.3 энтропия локальной части на РАСШИРЕННОЙ выборке.
Заявлено: 0 ложных на 24 живых, 7/7 ботовских."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')
from core.heuristics import looks_machine_generated, local_part_entropy

LEGIT = {
 "обычные имена": ["ivan.petrov@mail.ru","john.doe@gmail.com","anna-maria@web.de","jsmith@corp.com",
                   "m.gonzalez@empresa.es","olga_ivanova@yandex.ru","pierre.dupont@free.fr"],
 "слитные имена без разделителей": ["alexandrapetrova@gmail.com","michaeljohnson@gmail.com",
                   "wolfgangschmidt@web.de","francescarossi@libero.it","katarzynanowak@wp.pl"],
 "кириллические транслиты": ["vyacheslavshchepkin@mail.ru","zhdanovkrzysztof@gmail.com",
                   "bogdantsybin@gmail.com","dzhamshutrahmatov@mail.ru","shchvetsovvv@yandex.ru",
                   "krzysztofszczepanski@wp.pl"],
 "азиатские латинизации": ["zhangwei@163.com","nguyenthithanhhuong@gmail.com","wkrishnamurthy@qq.com",
                   "srisuwanwongsakul@gmail.com","chenxiaoming@126.com","phuongnguyenhoang@gmail.com",
                   "kimseonghyeon@naver.com"],
 "корпоративные хэш/ID-логины": ["u8f34kd9@corp.com","emp0093471x@bigcorp.com","ab12cd34@company.io",
                   "x7k2m9p4@enterprise.net","svc7acct22@corp.com"],
 "Apple Private Relay / relay-сервисы": ["kp8x2mnq4t@privaterelay.appleid.com",
                   "d7f3k9xz2q@privaterelay.appleid.com","a4x9mk2p@duck.com",
                   "zx84nq7v@relay.firefox.com","p9k3m7xq2w@anonaddy.me"],
 "инициалы и короткие": ["aabbccdd@gmail.com","jjmm2024@gmail.com","mk1987ab@mail.ru"],
}
BOTS = ["xk3n9fj2q1x@gmail.com","a7f3k2m9x1@mail.ru","qwertyuiop123@gmail.com",
        "asdfghjkl99@mail.ru","zxcvbnm4477@gmail.com","kd8f9j2mx7q3@yandex.ru",
        "b3n7v2x9k4m1@gmail.com","1234567890ab@gmail.com","f9q2wz8xk3n7v@mail.ru",
        "qazwsxedc123@gmail.com"]

print("="*82); print("S4.3 ЭНТРОПИЯ — расширенная выборка"); print("="*82)
fp = []; total_legit = 0
for group, addrs in LEGIT.items():
    print(f"\n[{group}]")
    for a in addrs:
        total_legit += 1
        r = looks_machine_generated(a)
        loc = a.split('@')[0]
        if r: fp.append(a)
        mark = "  <-- ЛОЖНОЕ СРАБАТЫВАНИЕ (-20 живому человеку)" if r else ""
        print(f"   {'BOT ' if r else 'ok  '} {a:<44} H={local_part_entropy(loc):.2f}{mark}")

print(f"\n[заведомо ботовские]")
missed = []
for a in BOTS:
    r = looks_machine_generated(a)
    if not r: missed.append(a)
    print(f"   {'BOT ' if r else 'MISS'} {a:<44} H={local_part_entropy(a.split('@')[0]):.2f}"
          f"{'' if r else '  <-- НЕ ПОЙМАН'}")

print("\n"+"="*82)
print(f"Живых адресов проверено:      {total_legit}")
print(f"ЛОЖНЫХ СРАБАТЫВАНИЙ:          {len(fp)}  ({len(fp)*100/total_legit:.1f}%)")
for a in fp: print(f"    - {a}")
print(f"Ботовских адресов проверено:  {len(BOTS)}")
print(f"ПРОПУЩЕНО ботов:              {len(missed)}  ({len(missed)*100/len(BOTS):.1f}%)")
for a in missed: print(f"    - {a}")
print("\nЗаявлено: 0 ложных на 24 живых, 7 из 7 ботовских.")
print(f"Фактически на {total_legit} живых: {len(fp)} ложных; на {len(BOTS)} ботовских поймано {len(BOTS)-len(missed)}.")
