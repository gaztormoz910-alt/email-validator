# -*- coding: utf-8 -*-
"""ФАЗА 4: РЕАЛЬНЫЕ строки почтовиков, попадающие в ловушку 'полный ящик'."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')
from core.network import NetworkValidator
v = NetworkValidator()
P = lambda c,m: v._parse_smtp_response(c, m.encode(), "u@d.com", "d.com")

# Это НЕ выдуманные строки — стандартные тексты Postfix/Exim/Sendmail.
REAL = [
 (452,"4.3.1 Insufficient system storage","Postfix: у СЕРВЕРА кончилось место на диске","НЕ про ящик"),
 (452,"4.3.1 Insufficient system resources","Postfix: нехватка ресурсов сервера","НЕ про ящик"),
 (421,"4.3.2 System not accepting network messages","Postfix: сервер не принимает почту","НЕ про ящик"),
 (452,"4.5.3 Too many recipients","Postfix: лимит получателей","НЕ про ящик"),
 (552,"5.2.2 Over quota","Exim: ящик переполнен","про ящик — valid ВЕРНО"),
 (452,"4.2.2 The email account that you tried to reach is over quota","Gmail: переполнен","про ящик — valid ВЕРНО"),
]
print("="*94)
print("S3.3/S4.2 — стандартные строки MTA против правила 'полный ящик = valid'")
print("="*94)
for code,msg,src,expect in REAL:
    r = P(code,msg)
    wrong = (r['status']=='valid' and 'НЕ про ящик' in expect)
    print(f"  {code} {msg:<58} -> {r['status']:<8} {'<-- ЛОЖНЫЙ VALID (+70 в скоринге)' if wrong else ''}")
    print(f"       источник: {src}   ожидаемо: {expect}")
