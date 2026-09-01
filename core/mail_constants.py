import zlib
# core/mail_constants.py
"""Таблицы, которыми пользуются сразу несколько слоёв проверки.

Здесь нет ни одной строки логики — только знание о том, как ведут себя чужие
почтовые серверы. Вынесено отдельно, потому что этими же таблицами
пользуются и SMTP-диалог, и профилирование прокси, и проверки по DNS, и
скоринг: пока они лежали внутри сетевого клиента, любой сосед вынужден был
импортировать их оттуда, и модули оказывались связаны через файл, к их работе
отношения не имеющий.

Всё, что здесь перечислено, ПРОВЕРЕНО живыми пробами, а не взято из
документации: поведение почтовиков меняется и почти нигде не описано честно.
"""

# Список доменов, известных как трудные для валидации или требующие специальной обработки
YAHOO_DOMAINS = {
    "yahoo.com", "yahoo.co.uk", "yahoo.co.in", "yahoo.fr", "yahoo.de",
    "yahoo.es", "yahoo.it", "yahoo.com.br", "yahoo.com.ar", "yahoo.com.mx",
    "yahoo.com.au", "yahoo.com.sg", "yahoo.com.hk", "yahoo.com.ph",
    "yahoo.gr", "yahoo.ro", "yahoo.hu", "yahoo.se", "yahoo.no", "yahoo.dk",
    "ymail.com", "rocketmail.com"
}

AOL_DOMAINS = {"aol.com", "aim.com", "verizon.net"}

# Провайдеры, которые режут по РЕПУТАЦИИ исходящего IP. Проверено вживую:
# Outlook отвечает "550 5.7.1 Service unavailable, Client host [IP]",
# iCloud — "550 Mail from IP ... rejected", GMX рвёт соединение.
# Через прокси из чёрных списков они молчат, через чистые — отвечают.
NEEDS_CLEAN_IP_DOMAINS = {
    "outlook.com", "hotmail.com", "live.com", "msn.com", "hotmail.co.uk",
    "hotmail.fr", "hotmail.de", "hotmail.es", "hotmail.it", "live.co.uk",
    "live.fr", "passport.com",
    "icloud.com", "me.com", "mac.com",
    "gmx.com", "gmx.de", "gmx.net", "gmx.at",
    # Apple Private Relay сидит на той же инфраструктуре, что и iCloud, и
    # режет по репутации так же. Раньше домен был известен скорингу и списку
    # одноразовых, но не маршрутизации — и проверялся грязным прокси, получая
    # отказ, который выглядел как проблема ящика.
    "privaterelay.appleid.com",
    # Китайские и корейские почтовики к чужим IP относятся строже прочих:
    # с адреса из чёрных списков они молчат, а молчание неотличимо от отказа.
    "qq.com", "foxmail.com", "163.com", "126.com", "yeah.net", "naver.com",
}

# Почтовики, которым нужен свой путь, но не чистый IP: отвечают честно любому.
# Держим их отдельным множеством, чтобы classify_domain и скоринг не считали
# их корпоративными доменами.
NICHE_FREE_DOMAINS = {
    "zoho.com", "zohomail.com", "zoho.eu", "zoho.in",
    "naver.com", "hanmail.net", "daum.net",
    "qq.com", "foxmail.com", "163.com", "126.com", "yeah.net",
}

MICROSOFT_DOMAINS = {
    "outlook.com", "hotmail.com", "hotmail.co.uk", "hotmail.fr", "hotmail.de",
    "hotmail.es", "hotmail.it", "live.com", "live.co.uk", "live.fr",
    "msn.com", "passport.com"
}

# HELO имена, которые выглядят как настоящие почтовые серверы (не как случайное имя ПК)
LEGIT_HELO_NAMES = [
    "mail.outbound-01.net",
    "smtp.delivery-gateway.com",
    "mta01.mailforward.net",
    "relay.outbound-smtp.org",
    "smtp-out.mailhost.net",
    "mx01.emailgateway.net",
]

# Чёрные списки почтовых серверов.
#
# Состав проверен санити-контрактом 2026-08-23: у каждой зоны запрошены
# обязательная тестовая запись 127.0.0.2 (должна числиться) и 127.0.0.1
# (не должна). Отсеяны нерабочие: zen.spamhaus.org отклоняет запросы с
# публичных DNS, cbl.abuseat.org влит в Spamhaus XBL, dnsbl.sorbs.net
# выведен из эксплуатации — все три давали NXDOMAIN даже на 127.0.0.2,
# то есть числились в коде, но не работали.
DNSBL_ZONES = [
    'b.barracudacentral.org',
    'bl.spamcop.net',
    'psbl.surriel.com',
    'truncate.gbudb.net',
    'all.s5h.net',
    'bl.mailspike.net',
    'dnsbl.dronebl.org',
]

# Spamhaus ZEN — крупнейший список, и его отсутствие было заметной дырой.
# Он отклоняет запросы, пришедшие с ПУБЛИЧНЫХ резолверов (8.8.8.8, 1.1.1.1),
# и поэтому раньше давал NXDOMAIN даже на обязательную тестовую запись
# 127.0.0.2 — то есть числился в коде, но не работал, и был убран.
#
# Работает он через СВОЙ резолвер: рекурсивный на том же VPS либо любой
# непубличный, который согласится обслуживать зону. Поэтому Spamhaus вынесен
# отдельно: спрашивается только когда такой резолвер задан, а перед первым
# запросом проверяется санити-контрактом — 127.0.0.2 обязана числиться,
# 127.0.0.1 обязана не числиться. Не прошёл контракт — зона не используется,
# и её молчание НЕ считается чистотой адреса.
SPAMHAUS_ZONE = 'zen.spamhaus.org'

# Обязательные тестовые записи Spamhaus (документированы им самим)
SPAMHAUS_SANITY_LISTED = '2.0.0.127'      # обязана числиться
SPAMHAUS_SANITY_CLEAN = '1.0.0.127'       # обязана НЕ числиться

# Сколько сбоев ПОДРЯД должен дать прокси, чтобы вылететь из ротации навсегда.
# Один-два сбоя бывают случайными (таймаут, занятый MX), три подряд — прокси мёртв.
PROXY_MAX_CONSECUTIVE_FAILS = 3

# Пул правдоподобных адресов для ротации MAIL FROM (п.3.2)
# Обратные адреса для команды MAIL FROM.
#
# У каждого домена здесь ДОЛЖНА быть настоящая MX-запись. Раньше половину пула
# составляли example.com, example.net и example.org — замерено: у всех трёх
# Null MX (RFC 7505), то есть домен сам объявляет «почту не принимаю». RFC 7505
# §4 прямо велит отвергать такого отправителя кодом 550, и строгий сервер так
# и делает: до вопроса о ЯЩИКЕ дело не доходит, адрес остаётся без вердикта.
#
# Gmail и Яндекс их пропускают — проверено, — но настраивать проверку по двум
# самым терпимым серверам значит терять ответы на всех остальных.
MAIL_FROM_POOL = [
    "check@mail.com",
    "verify@email.com",
    "noreply@usa.com",
    "check@gmx.com",
    "verify@post.com",
    "noreply@writeme.com",
]


# Режим SPF у доменов обратного адреса. Замерено 2026-09-02 через 8.8.8.8:
# все шесть по redirect= приходят к _spf.mail.com или _spf.gmx.net, и оба
# кончаются "~all".
#
# Зачем таблица. Строгий "-all" означает «письма с чужих IP — подделка», а мы
# приходим именно с чужого: строгий сервер отвергнет наш MAIL FROM, и до
# вопроса о ящике дело не дойдёт. Проверять это надо ДО того, как ставить
# адрес в пул, а не после жалоб на сплошные unknown. Тест рядом следит, чтобы
# в пул нельзя было добавить адрес, не замерив его.
MAIL_FROM_SPF_MODE = {
    "mail.com": "~all",
    "email.com": "~all",
    "usa.com": "~all",
    "gmx.com": "~all",
    "post.com": "~all",
    "writeme.com": "~all",
}


def mail_from_for(domain):
    """Обратный адрес для домена получателя. Один и тот же при каждой попытке.

    Раньше здесь стоял random.choice на КАЖДУЮ попытку, и это тихо ломало
    работу с серыми списками. Greylisting ведётся по тройке (наш IP, наш
    отправитель, получатель): сервер отвечает «приходите позже» и ждёт, что
    та же тройка вернётся после выдержки. Со случайным отправителем тройка не
    совпадала никогда — сервер видел нового отправителя и отвечал «позже»
    снова, сколько бы мы ни повторяли.

    Ротация при этом никуда не делась: разным доменам достаются разные
    адреса из пула, и один почтовик по-прежнему не видит всю базу за одним
    отправителем. Разбрасывает crc32, а не hash(): встроенный hash() в
    Python рандомизируется при каждом запуске, и «стабильный» выбор менялся
    бы между прогонами — то есть ровно там, где стабильность и нужна.
    """
    if not isinstance(domain, str) or not domain:
        return MAIL_FROM_POOL[0]
    index = zlib.crc32(domain.strip().lower().encode("utf-8", "ignore"))
    return MAIL_FROM_POOL[index % len(MAIL_FROM_POOL)]

# TLD: либо обычные буквы, либо punycode-зона IDN (xn--p1ai для .рф, xn--80asehdb
# для .онлайн). Без второй половины любой интернационализированный домен после
# перевода в punycode не проходил регулярку и получал вердикт «Bad Syntax».
# Синтаксис адреса и IDN живут в core/email_syntax.py: это единственный

_DKIM_BY_MX = (
    (("google", "googlemail"), ['google', '20230601', '20221208', '20210112', '20161025']),
    (("outlook", "microsoft", "protection.outlook"), ['selector1', 'selector2']),
    (("yandex",), ['mx', 'yandex']),
    (("mail.ru",), ['mailru', 'mail']),
    (("protonmail", "proton.me"), ['protonmail', 'protonmail2', 'protonmail3']),
    (("zoho",), ['zoho', 'zmail']),
    (("yahoodns",), ['s2048', 's1024']),
    (("messagingengine", "fastmail"), ['fm1', 'fm2', 'fm3', 'mesmtp']),
    (("amazonaws", "amazonses"), ['amazonses']),
    (("sendgrid",), ['s1', 's2']),
    (("mailgun",), ['mailo', 'smtp', 'k1']),
)

_DKIM_FALLBACK = [
    'google', '20230601', 'selector1', 'selector2', 'mailru', 'mail', 'dkim',
    'default', 'mx', 'yandex', 'protonmail', 'zoho', 'k1', 'k2', 's1', 's2',
    'sig1', 'smtp', 'key1', 'dkim1', '20221208', '20210112', 'zmail',
]

def _dkim_selectors_for(mx_record):
    """Список селекторов под конкретный MX. Без MX — общий перебор."""
    if isinstance(mx_record, str) and mx_record and mx_record != "N/A":
        low = mx_record.lower()
        for hints, selectors in _DKIM_BY_MX:
            if any(hint in low for hint in hints):
                # Плюс два самых частых общих — на случай своей подписи домена
                return selectors + ['default', 'dkim']
    return _DKIM_FALLBACK


# Почтовые шлюзы безопасности. Стоят ПЕРЕД корпоративным доменом и принимают
# любой RCPT, фильтруя письмо позже, — то есть домен за таким шлюзом является
# catch-all по конструкции. Проверено на практике: тройная проба выясняет это
# верно, но тратит три подключения и не объясняет причину.
SECURITY_GATEWAY_MX = {
    "pphosted.com": "Proofpoint",
    "ppe-hosted.com": "Proofpoint",
    "pphosted.net": "Proofpoint",
    "mimecast.com": "Mimecast",
    "mimecast.co.za": "Mimecast",
    "mimecast-offshore.com": "Mimecast",
    "iphmx.com": "Cisco IronPort",
    "barracudanetworks.com": "Barracuda",
    "barracuda.com": "Barracuda",
    "messagelabs.com": "Symantec",
    "sophos.com": "Sophos",
    "fortimail.com": "Fortinet",
    "hornetsecurity.com": "Hornetsecurity",
    "antispamcloud.com": "SpamExperts",
    "spamexperts.com": "SpamExperts",
    "mailcontrol.com": "Forcepoint",
    "securence.com": "Securence",
    "spamtitan.com": "SpamTitan",
    "mailanyone.net": "FuseMail",
    "emailfiltering.com": "Email Filtering",
    "mailprotector.com": "Mailprotector",
    "mailguard.com.au": "MailGuard",
    "libraesva.com": "Libraesva",
    "vadesecure.com": "Vade",
    "abusix.com": "Abusix",
}
