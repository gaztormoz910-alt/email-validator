#!/usr/bin/env python
"""Собирает bash-скрипт, который поднимает свой SOCKS5 на чистом VPS.

Зачем это в проекте с валидатором. Разбор ответов сервера, детектор catch-all
и проверка postmaster упираются в одно: почтовик должен вообще согласиться
разговаривать с нашим адресом. Yahoo и AOL требуют обратную запись (PTR),
Outlook и iCloud смотрят на репутацию. Бесплатные прокси не дают ни того, ни
другого — они лежат в Spamhaus PBL по определению, потому что это адреса
чужих взломанных машин.

Один VPS за несколько долларов закрывает вопрос целиком: статичный адрес,
PTR от хостера, чистая репутация и открытый порт 25. Купить сервер за
владельца нельзя, а убрать всю остальную работу — можно.

Порт 25 у многих хостеров закрыт по умолчанию и открывается по запросу в
поддержку — об этом сказано в самом скрипте, потому что без него всё
остальное бессмысленно.

Запуск:
    python tools/make_vps_proxy.py --user myname --password S3cret > setup.sh

Дальше: закинуть setup.sh на свежий VPS и выполнить от root.
"""
import argparse
import os
import secrets
import string
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

DEFAULT_PORT = 1080


def strong_password(length=20):
    """Пароль, который не стыдно оставить в конфиге на сервере."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def build_script(user, password, port=DEFAULT_PORT):
    """Текст bash-скрипта. Ничего не выполняет — только собирает."""
    return f"""#!/bin/bash
# Свой SOCKS5 для валидации почты. Выполнять от root на СВЕЖЕМ VPS.
#
# Что делает:
#   1. ставит 3proxy;
#   2. поднимает SOCKS5 на порту {port} с логином и паролем;
#   3. открывает этот порт в firewall;
#   4. включает автозапуск;
#   5. проверяет, открыт ли исходящий порт 25 — без него валидация
#      невозможна, и лучше узнать об этом сразу.
set -e

echo "==> Ставлю 3proxy"
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq 3proxy netcat-openbsd curl >/dev/null
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q 3proxy nmap-ncat curl >/dev/null
else
    echo "Неизвестный дистрибутив: поставьте 3proxy вручную" >&2
    exit 1
fi

echo "==> Пишу конфиг"
mkdir -p /etc/3proxy
cat > /etc/3proxy/3proxy.cfg <<'CFG'
daemon
maxconn 2000
nserver 1.1.1.1
nserver 8.8.8.8
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
users {user}:CL:{password}
auth strong
allow {user}
socks -p{port}
CFG
chmod 600 /etc/3proxy/3proxy.cfg

echo "==> Автозапуск"
cat > /etc/systemd/system/3proxy.service <<'UNIT'
[Unit]
Description=3proxy SOCKS5
After=network.target

[Service]
ExecStart=/usr/bin/3proxy /etc/3proxy/3proxy.cfg
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now 3proxy

echo "==> Открываю порт {port}"
if command -v ufw >/dev/null 2>&1; then
    ufw allow {port}/tcp >/dev/null 2>&1 || true
elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port={port}/tcp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
fi

IP=$(curl -s --max-time 10 https://api.ipify.org || echo "не определился")

echo
echo "==> Проверяю исходящий порт 25 (без него валидация не работает)"
if nc -z -w 8 gmail-smtp-in.l.google.com 25 2>/dev/null; then
    echo "    порт 25 ОТКРЫТ — всё готово"
else
    echo "    порт 25 ЗАКРЫТ."
    echo "    Хостеры закрывают его по умолчанию против спама."
    echo "    Напишите в поддержку: просите разблокировать исходящий 25/tcp."
    echo "    Порты 587 и 465 НЕ подойдут: они для отправки через релей."
fi

echo
echo "==> Проверяю обратную запись (PTR) — её требуют Yahoo и AOL"
PTR=$(getent hosts "$IP" 2>/dev/null | awk '{{print $2}}' || true)
if [ -n "$PTR" ]; then
    echo "    PTR есть: $PTR"
else
    echo "    PTR НЕТ. Задаётся в панели хостера (Reverse DNS)."
    echo "    Без него Yahoo и AOL отвечают 550 5.7.25 и до проверки ящика"
    echo "    дело не доходит."
fi

echo
echo "================================================================"
echo "Строка для валидатора (вставьте в поле «Прокси»):"
echo
echo "    socks5://{user}:{password}@$IP:{port}"
echo
echo "================================================================"
"""


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Собирает скрипт подъёма своего SOCKS5 на VPS")
    parser.add_argument("--user", default="validator",
                        help="логин прокси (по умолчанию validator)")
    parser.add_argument("--password", default="",
                        help="пароль; если не задан — будет сгенерирован")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="порт SOCKS5 (по умолчанию %d)" % DEFAULT_PORT)
    parser.add_argument("--out", default="",
                        help="куда записать; по умолчанию в стандартный вывод")
    args = parser.parse_args(argv)

    password = args.password or strong_password()
    port = max(1, min(65535, int(args.port)))
    script = build_script(args.user, password, port)

    if args.out:
        directory = os.path.dirname(args.out)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(script)
        print("Скрипт записан: %s" % args.out)
        print("Загрузите его на свежий VPS и выполните от root.")
        if not args.password:
            print("Сгенерированный пароль прокси: %s" % password)
    else:
        sys.stdout.write(script)
    return 0


if __name__ == "__main__":
    sys.exit(main())
