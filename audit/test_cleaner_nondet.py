# -*- coding: utf-8 -*-
"""ФАЗА 4: недетерминированность очистки домена (S1.3).
Первый цикл (startswith) отрабатывает раньше, поэтому предыдущий кейс до
второго цикла не доходил. Строим домен, который попадает именно во второй цикл:
не начинается ни с одного известного домена, точек > 3, внутри ДВА известных домена.
"""
import sys, os, subprocess
sys.stdout.reconfigure(encoding='utf-8')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

print("hash-рандомизация активна:",
      subprocess.run([sys.executable,"-c","print(hash('gmail.com'))"],capture_output=True,text=True).stdout.strip(),
      subprocess.run([sys.executable,"-c","print(hash('gmail.com'))"],capture_output=True,text=True).stdout.strip())

PROBES = ["x.gmail.com.y.yahoo.com.z", "a.hotmail.com.b.live.com.c.d", "q.yahoo.co.uk.w.gmail.com.e"]
for probe in PROBES:
    outs = {}
    for i in range(25):
        r = subprocess.run([sys.executable, "-c",
            f"import sys;sys.path.insert(0,r'{ROOT}');from core.cleaner import EmailCleaner;"
            f"print(EmailCleaner().clean_email('bob@{probe}'))"],
            capture_output=True, text=True)
        o = r.stdout.strip(); outs[o] = outs.get(o,0)+1
    status = "НЕДЕТЕРМИНИРОВАН" if len(outs) > 1 else "стабилен"
    print(f"\n  bob@{probe}")
    print(f"    25 запусков -> {len(outs)} различных результатов  [{status}]")
    for o,n in sorted(outs.items(), key=lambda x:-x[1]):
        print(f"       {n:>3}x  {o}")
