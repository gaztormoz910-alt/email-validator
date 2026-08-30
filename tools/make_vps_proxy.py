#!/usr/bin/env python
"""Собирает bash-скрипт, который поднимает свой SOCKS5 на чистом VPS.

Зачем это в проекте с валидатором. Разбор ответов сервера, детектор catch-all
и проверка postmaster упираются в одно: почтовик должен вообще согласиться
разговаривать с нашим адресом. Yahoo и AOL требуют обратную запись (PTR),
Outlook и iCloud смотрят на репутацию. Бесплатные прокси не дают ни того, ни
другого — это адреса чужих взломанных машин, и они лежат в Spamhaus PBL по
определению.

Один VPS за пару долларов закрывает вопрос: статичный адрес, PTR от хостера,
чистая репутация и открытый порт 25. Купить сервер за владельца нельзя, а
убрать всю остальную работу — можно.

Что здесь исправлено против первой версии:

  * 3proxy СОБИРАЕТСЯ ИЗ ИСХОДНИКОВ. Первая версия ставила его через
    `apt-get install 3proxy`, а такого пакета нет ни в Ubuntu 22.04, ни в
    24.04 — скрипт падал на первом же шаге с `set -e`, и владелец получал
    сервер без прокси и без объяснения;
  * порт SSH открывается в firewall ДО его включения, и он настраиваемый.
    Иначе `ufw --force enable` с нестандартным SSH-портом отрезает доступ к
    серверу, и чинить это можно только через консоль хостера;
  * проверка, что скрипт запущен от root, и что система на apt;
  * конфиг с паролем кладётся в режиме 600 — иначе пароль от прокси читает
    любой пользователь сервера.

Порт 25 у многих хостеров закрыт по умолчанию и открывается по запросу в
поддержку. Скрипт проверяет это сам и говорит прямо, потому что без порта 25
всё остальное бессмысленно.

Запуск:
    python tools/make_vps_proxy.py --out setup.sh
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
DEFAULT_SSH_PORT = 22

# Версия 3proxy, которая собирается. Прибита намеренно: «последняя» означает,
# что однажды скрипт соберёт то, чего никто не проверял.
THREEPROXY_VERSION = "0.9.5"

# Сколько одновременных соединений держит прокси. Валидатор ходит в триста
# потоков, и общий предел ниже этого числа сделал бы прокси узким местом —
# соединения вставали бы в очередь, а владелец видел бы таймауты и решил, что
# виноват почтовик.
MAX_CONNECTIONS = 512


def strong_password(length=20):
    """Пароль, который не стыдно оставить в конфиге на сервере."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def build_script(user, password, port=DEFAULT_PORT, ssh_port=DEFAULT_SSH_PORT):
    """Текст bash-скрипта. Ничего не выполняет — только собирает."""
    return f"""#!/bin/bash
# Свой SOCKS5 для валидации почты. Выполнять от root на СВЕЖЕМ VPS
# (Ubuntu 22.04/24.04 или Debian 12, минимальный образ без панелей).
#
# Что делает:
#   1. проверяет, что запущен от root и что система на apt;
#   2. собирает 3proxy {THREEPROXY_VERSION} из исходников;
#   3. поднимает SOCKS5 на порту {port} с логином и паролем;
#   4. открывает в firewall SSH ({ssh_port}) И порт прокси, потом включает ufw;
#   5. вешает автозапуск, чтобы прокси пережил перезагрузку;
#   6. проверяет исходящий порт 25 и обратную запись (PTR) — без них
#      валидация невозможна, и лучше узнать об этом сразу.
set -euo pipefail

PROXY_PORT={port}
SSH_PORT={ssh_port}
PROXY_USER="{user}"
PROXY_PASS="{password}"
V={THREEPROXY_VERSION}

if [ "$(id -u)" != "0" ]; then
    echo "Нужны права root: запустите через sudo или зайдите под root." >&2
    exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
    echo "Скрипт рассчитан на Ubuntu/Debian (apt). На CentOS/Alma он не пойдёт." >&2
    exit 1
fi

echo ">>> Ставлю зависимости"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential wget tar curl ufw netcat-openbsd dnsutils

echo ">>> Собираю 3proxy $V из исходников"
# Пакета 3proxy нет в репозиториях Ubuntu 22.04/24.04 — только сборка.
cd /tmp
rm -rf 3proxy-* 3proxy.tar.gz
wget -qO 3proxy.tar.gz "https://github.com/3proxy/3proxy/archive/refs/tags/$V.tar.gz"
tar -xzf 3proxy.tar.gz
cd "3proxy-$V"
make -f Makefile.Linux >/dev/null
mkdir -p /etc/3proxy /var/log/3proxy
cp bin/3proxy /usr/local/bin/3proxy

echo ">>> Пишу конфиг"
cat > /etc/3proxy/3proxy.cfg <<CFG
daemon
maxconn {MAX_CONNECTIONS}
nserver 1.1.1.1
nserver 8.8.8.8
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
log /var/log/3proxy/3proxy.log D
rotate 7
users $PROXY_USER:CL:$PROXY_PASS
auth strong
allow $PROXY_USER
socks -p$PROXY_PORT
CFG
# Пароль в конфиге лежит открытым текстом — таков формат 3proxy. Значит файл
# не должен читаться никем, кроме root.
chmod 600 /etc/3proxy/3proxy.cfg

echo ">>> Автозапуск"
cat > /etc/systemd/system/3proxy.service <<UNIT
[Unit]
Description=3proxy SOCKS5
After=network.target

[Service]
ExecStart=/usr/local/bin/3proxy /etc/3proxy/3proxy.cfg
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable 3proxy >/dev/null 2>&1
systemctl restart 3proxy

echo ">>> Firewall"
# SSH открывается ПЕРВЫМ и до включения ufw. Обратный порядок отрезает доступ
# к серверу, и чинится это только через консоль хостера.
ufw allow "$SSH_PORT"/tcp >/dev/null
ufw allow "$PROXY_PORT"/tcp >/dev/null
ufw --force enable >/dev/null

sleep 1
if ! systemctl is-active --quiet 3proxy; then
    echo "3proxy не запустился. Смотрите: journalctl -u 3proxy -n 30" >&2
    exit 1
fi

IP=$(curl -s --max-time 10 https://api.ipify.org || hostname -I | awk '{{print $1}}')

echo
echo ">>> Проверяю исходящий порт 25 (без него валидация не работает)"
if nc -z -w 8 gmail-smtp-in.l.google.com 25 2>/dev/null; then
    echo "    порт 25 ОТКРЫТ"
else
    echo "    порт 25 ЗАКРЫТ."
    echo "    Хостеры закрывают его по умолчанию против спама."
    echo "    Напишите в поддержку: просите разблокировать исходящий 25/tcp."
    echo "    Порты 587 и 465 НЕ подойдут: они для отправки через релей,"
    echo "    а проверка ящика идёт только по 25."
fi

echo
echo ">>> Проверяю обратную запись (PTR) — её требуют Yahoo и AOL"
PTR=$(dig +short -x "$IP" 2>/dev/null | head -1)
if [ -n "$PTR" ]; then
    echo "    PTR есть: $PTR"
else
    echo "    PTR НЕТ. Задаётся в панели хостера (Reverse DNS)."
    echo "    Без него Yahoo и AOL отвечают 550 5.7.25 ещё на MAIL FROM,"
    echo "    и до проверки ящика дело не доходит."
fi

echo
echo "================================================================"
echo "Строка для валидатора (вставьте в поле «Прокси»):"
echo
echo "    socks5://$PROXY_USER:$PROXY_PASS@$IP:$PROXY_PORT"
echo
echo "Проверить прокси можно самим валидатором: он покажет готовность"
echo "по каждому почтовику ещё до начала прогона."
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
    parser.add_argument("--ssh-port", type=int, default=DEFAULT_SSH_PORT,
                        help="порт SSH вашего сервера; он будет открыт в "
                             "firewall до его включения (по умолчанию %d)"
                             % DEFAULT_SSH_PORT)
    parser.add_argument("--out", default="",
                        help="куда записать; по умолчанию в стандартный вывод")
    args = parser.parse_args(argv)

    password = args.password or strong_password()
    port = max(1, min(65535, int(args.port)))
    ssh_port = max(1, min(65535, int(args.ssh_port)))
    script = build_script(args.user, password, port, ssh_port)

    if args.out:
        directory = os.path.dirname(args.out)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(script)
        print("Скрипт записан: %s" % args.out)
        print("Загрузите его на свежий VPS и выполните от root.")
        if ssh_port != DEFAULT_SSH_PORT:
            print("Порт SSH в скрипте: %d — проверьте, что он верный, иначе "
                  "firewall отрежет доступ." % ssh_port)
        if not args.password:
            print("Сгенерированный пароль прокси: %s" % password)
    else:
        sys.stdout.write(script)
    return 0


if __name__ == "__main__":
    sys.exit(main())
