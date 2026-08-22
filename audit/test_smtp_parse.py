# -*- coding: utf-8 -*-
"""ФАЗА 3: S3.3 классификация SMTP-ответов + S4.2 полный ящик + S3.2 MAIL FROM."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')
from core.network import NetworkValidator
v = NetworkValidator()
P = lambda c,m: v._parse_smtp_response(c, m.encode(), "u@d.com", "d.com")

CASES = [
 (250,"2.1.5 OK","valid"),
 (552,"5.2.2 Requested mail action aborted: exceeded storage allocation","valid"),
 (452,"4.2.2 Mailbox full","valid"),
 (450,"4.7.1 Greylisted, please try again in 300 seconds","greylisted"),
 (450,"4.2.0 Try again later","greylisted"),
 (450,"4.7.1 Rate limited, too many connections","unknown"),
 (451,"4.3.0 Temporary local problem","greylisted"),
 (421,"4.7.0 Too many connections, service busy","unknown"),
 (550,"5.1.1 The email account that you tried to reach does not exist","invalid"),
 (550,"5.1.1 User unknown","invalid"),
 (550,"5.7.1 Service unavailable, client host blocked using Spamhaus","unknown"),
 (550,"5.7.1 Sender verify failed","unknown"),
 (550,"5.2.1 The account has been disabled or discontinued","invalid"),
 (550,"5.2.1 Mailbox is suspended","risky"),
 (550,"Rejected","risky"),
 (551,"User not local","invalid"),
 (553,"5.1.3 Bad recipient address syntax","invalid"),
 (554,"5.7.1 Your IP is blacklisted","unknown"),
 (554,"5.0.0 Transaction failed","unknown"),
 (500,"Syntax error","unknown"),
 (503,"5.5.1 Bad sequence of commands","unknown"),
 (521,"Domain does not accept mail","unknown"),
 (530,"5.7.0 Authentication required","unknown"),
 (535,"5.7.8 Authentication credentials invalid","unknown"),
 (571,"5.7.1 Delivery not authorized","unknown"),
 (556,"5.1.10 Recipient address has null MX","risky"),
 (471,"4.0.0 Some temp error","unknown"),
 (999,"weird","unknown"),
]
print("="*88); print("S3.3 КЛАССИФИКАЦИЯ SMTP-ОТВЕТОВ (реальный код, без моков)"); print("="*88)
bad = 0
seen_status = {}
for code,msg,exp in CASES:
    r = P(code,msg)
    ok = r['status']==exp
    if not ok: bad += 1
    seen_status[r['status']] = seen_status.get(r['status'],0)+1
    print(f"  [{'OK ' if ok else 'РАСХ'}] {code} {msg[:52]:<54} -> {r['status']:<10} ({r['reason'][:34]})")
print(f"\n  Сценариев проверено: {len(CASES)};  расхождений: {bad}")
print(f"  Распределение вердиктов: {seen_status}")

print("\n"+"="*88); print("АДВЕРСАРИАЛЬНО: подстрочный матч ДО разбора кода"); print("="*88)
TRAPS = [
 (550,"5.1.1 no such user; contact storage administrator","ловушка: слово 'storage' в 550"),
 (550,"5.1.1 User unknown in virtual mailbox table (over quota check)","ловушка: 'over quota' в 550"),
 (421,"4.7.0 mailbox full of spam complaints, closing connection","ловушка: 'mailbox full' в 421"),
 (554,"5.7.1 rejected, storage backend unavailable","ловушка: 'storage' в 554"),
]
for code,msg,note in TRAPS:
    r = P(code,msg)
    flag = "  <-- ЛОЖНЫЙ 'valid'!" if r['status']=='valid' else ""
    print(f"  {code} {msg[:60]:<62} -> {r['status']:<8}{flag}   {note}")
print("  Причина: проверка `code==552 or 'over quota' in msg or 'storage' in msg or")
print("  'mailbox full' in msg` стоит ВЫШЕ разбора 550/554 и матчится по любому коду.")
