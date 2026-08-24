# core/provider.py
"""Классификация почтового провайдера и типа домена (п.34, п.35, п.38 чек-листа).

Отвечает на два разных вопроса:
  provider_name — ЧЕЙ это почтовик (Gmail / Yahoo / Outlook / Mail.ru / ...)
  domain_type   — ЧТО это за домен (Personal / Corporate / ISP / Education / Government)

Нужно для сегментации базы: рассылка на Gmail и на корпоративные домены
ведёт себя по-разному (разные лимиты, разные пороги жалоб).
"""

from collections import Counter

# Провайдер -> его домены
_PROVIDER_DOMAINS = {
    "Gmail": {"gmail.com", "googlemail.com"},
    "Outlook": {"outlook.com", "hotmail.com", "live.com", "msn.com",
                "outlook.co.uk", "hotmail.co.uk", "live.co.uk", "passport.com"},
    "Yahoo": {"yahoo.com", "ymail.com", "rocketmail.com", "yahoo.co.uk",
              "yahoo.fr", "yahoo.de", "yahoo.co.jp", "yahoo.in", "yahoo.ca"},
    "Mail.ru": {"mail.ru", "bk.ru", "inbox.ru", "list.ru", "internet.ru"},
    "Yandex": {"yandex.ru", "ya.ru", "yandex.com", "yandex.by", "yandex.kz"},
    "iCloud": {"icloud.com", "me.com", "mac.com"},
    "Proton": {"protonmail.com", "protonmail.ch", "proton.me", "pm.me"},
    "AOL": {"aol.com", "aim.com", "love.com", "games.com"},
    "GMX": {"gmx.com", "gmx.de", "gmx.net", "gmx.at"},
    "Zoho": {"zoho.com", "zohomail.com"},
    "Tutanota": {"tutanota.com", "tuta.io", "tutanota.de"},
    "Fastmail": {"fastmail.com", "fastmail.fm"},
    "QQ": {"qq.com", "foxmail.com"},
    "NetEase": {"163.com", "126.com", "yeah.net"},
}

# Плоская карта домен -> провайдер (строится один раз при импорте)
_DOMAIN_TO_PROVIDER = {}
for _prov, _domains in _PROVIDER_DOMAINS.items():
    for _d in _domains:
        _DOMAIN_TO_PROVIDER[_d] = _prov

# Интернет-провайдеры (ISP). Такие ящики выдаются вместе с интернетом
# и часто умирают при смене оператора — это важный сигнал риска.
_ISP_DOMAINS = {
    "comcast.net", "verizon.net", "att.net", "sbcglobal.net", "bellsouth.net",
    "cox.net", "charter.net", "earthlink.net", "juno.com", "netzero.net",
    "optonline.net", "roadrunner.com", "rr.com", "windstream.net", "frontier.com",
    "centurylink.net", "embarqmail.com", "shaw.ca", "rogers.com", "sympatico.ca",
    "telus.net", "bigpond.com", "optusnet.com.au", "virginmedia.com", "sky.com",
    "btinternet.com", "talktalk.net", "orange.fr", "wanadoo.fr", "free.fr",
    "t-online.de", "web.de", "libero.it", "terra.com.br", "uol.com.br",
}

# MX-хосты крупных хостеров: по ним понимаем, на чьей инфраструктуре сидит домен
_MX_PROVIDER_HINTS = {
    "google": "Google Workspace",
    "googlemail": "Google Workspace",
    "outlook": "Microsoft 365",
    "microsoft": "Microsoft 365",
    "protection.outlook": "Microsoft 365",
    "yandex": "Yandex 360",
    "mail.ru": "Mail.ru Biz",
    "zoho": "Zoho Mail",
    "protonmail": "Proton",
    "proton.me": "Proton",
    "yahoodns": "Yahoo",
    "secureserver": "GoDaddy",
    "mailgun": "Mailgun",
    "sendgrid": "SendGrid",
    "amazonaws": "Amazon SES",
    "qq.com": "QQ",
    # Почтовые хостеры среднего эшелона: раньше все они попадали в общий
    # "Corporate", и сегментировать базу по инфраструктуре было нельзя.
    "messagingengine": "Fastmail",
    "fastmail": "Fastmail",
    "migadu": "Migadu",
    "purelymail": "Purelymail",
    "mailbox.org": "Mailbox.org",
    "posteo": "Posteo",
    "runbox": "Runbox",
    "tutanota": "Tutanota",
    "tuta.com": "Tutanota",
    "emailsrvr": "Rackspace",
    "rackspace": "Rackspace",
    "hostedemail": "Openwave",
    "dreamhost": "DreamHost",
    "bluehost": "Bluehost",
    "hostinger": "Hostinger",
    "ionos": "IONOS",
    "1and1": "IONOS",
    "ovh.net": "OVH",
    "gandi.net": "Gandi",
    "namecheap": "Namecheap",
    "titan.email": "Titan",
    "improvmx": "ImprovMX",
    "forwardemail": "ForwardEmail",
    "zohomail": "Zoho Mail",
    "aliyun": "Alibaba Mail",
    "qiye.aliyun": "Alibaba Mail",
    "163.com": "NetEase",
    "126.com": "NetEase",
    "naver": "Naver",
    "daum": "Daum",
    "hinet": "HiNet",
    "sakura.ne.jp": "Sakura",
    "cloudflare": "Cloudflare Email Routing",
    "mailchannels": "MailChannels",
    "postmarkapp": "Postmark",
    "mandrillapp": "Mailchimp",
    "sparkpostmail": "SparkPost",
    "mimecast": "Mimecast",
    "pphosted": "Proofpoint",
    "ppe-hosted": "Proofpoint",
    "iphmx": "Cisco IronPort",
    "barracudanetworks": "Barracuda",
    "messagelabs": "Symantec",
    "trendmicro": "Trend Micro",
    "sophos": "Sophos",
    "fortimail": "Fortinet",
    "hornetsecurity": "Hornetsecurity",
    "antispamcloud": "SpamExperts",
    "spamexperts": "SpamExperts",
}

# Домен почтовика -> страна пользователя.
#
# Зачем: страна бралась ТОЛЬКО из TLD, а у .com и .net его нет — то есть у
# большей части US/EU базы страна оставалась пустой. При этом сам домен
# почтовика её знает точно: web.de — это Германия, orange.fr — Франция.
# Это гораздо более сильный сигнал, чем угадывание по имени.
_DOMAIN_COUNTRY = {
    # Германия
    "web.de": "Германия", "gmx.de": "Германия", "gmx.net": "Германия",
    "t-online.de": "Германия", "freenet.de": "Германия", "hotmail.de": "Германия",
    "yahoo.de": "Германия", "outlook.de": "Германия", "arcor.de": "Германия",
    "1und1.de": "Германия", "posteo.de": "Германия", "mailbox.org": "Германия",
    # Франция
    "orange.fr": "Франция", "free.fr": "Франция", "sfr.fr": "Франция",
    "laposte.net": "Франция", "wanadoo.fr": "Франция", "yahoo.fr": "Франция",
    "hotmail.fr": "Франция", "bbox.fr": "Франция", "neuf.fr": "Франция",
    "numericable.fr": "Франция", "aliceadsl.fr": "Франция",
    # Италия
    "libero.it": "Италия", "virgilio.it": "Италия", "tim.it": "Италия",
    "alice.it": "Италия", "tiscali.it": "Италия", "yahoo.it": "Италия",
    "hotmail.it": "Италия", "email.it": "Италия", "inwind.it": "Италия",
    "fastwebnet.it": "Италия", "poste.it": "Италия",
    # Испания
    "yahoo.es": "Испания", "hotmail.es": "Испания", "telefonica.net": "Испания",
    "terra.es": "Испания", "movistar.es": "Испания",
    # Великобритания
    "btinternet.com": "Великобритания", "sky.com": "Великобритания",
    "virginmedia.com": "Великобритания", "talktalk.net": "Великобритания",
    "blueyonder.co.uk": "Великобритания", "ntlworld.com": "Великобритания",
    "hotmail.co.uk": "Великобритания", "yahoo.co.uk": "Великобритания",
    "live.co.uk": "Великобритания", "outlook.co.uk": "Великобритания",
    "virgin.net": "Великобритания", "tiscali.co.uk": "Великобритания",
    # Нидерланды и Бельгия
    "ziggo.nl": "Нидерланды", "kpnmail.nl": "Нидерланды", "planet.nl": "Нидерланды",
    "hetnet.nl": "Нидерланды", "upcmail.nl": "Нидерланды", "chello.nl": "Нидерланды",
    "xs4all.nl": "Нидерланды", "hotmail.nl": "Нидерланды", "live.nl": "Нидерланды",
    "telenet.be": "Бельгия", "skynet.be": "Бельгия", "proximus.be": "Бельгия",
    # Польша
    "wp.pl": "Польша", "onet.pl": "Польша", "o2.pl": "Польша",
    "interia.pl": "Польша", "gazeta.pl": "Польша", "poczta.onet.pl": "Польша",
    # Россия и соседи
    "mail.ru": "Россия", "bk.ru": "Россия", "inbox.ru": "Россия",
    "list.ru": "Россия", "internet.ru": "Россия", "yandex.ru": "Россия",
    "ya.ru": "Россия", "rambler.ru": "Россия", "lenta.ru": "Россия",
    "autorambler.ru": "Россия", "bushmail.ru": "Россия",
    "ukr.net": "Украина", "i.ua": "Украина", "meta.ua": "Украина",
    "tut.by": "Беларусь", "yandex.by": "Беларусь",
    "yandex.kz": "Казахстан", "mail.kz": "Казахстан",
    # Скандинавия
    "telia.com": "Швеция", "bredband.net": "Швеция", "spray.se": "Швеция",
    "online.no": "Норвегия", "broadpark.no": "Норвегия",
    "sol.dk": "Дания", "mail.dk": "Дания",
    "luukku.com": "Финляндия", "suomi24.fi": "Финляндия",
    # США и Канада
    "comcast.net": "США", "sbcglobal.net": "США", "att.net": "США",
    "verizon.net": "США", "cox.net": "США", "charter.net": "США",
    "bellsouth.net": "США", "optonline.net": "США", "roadrunner.com": "США",
    "windstream.net": "США", "frontier.com": "США", "centurylink.net": "США",
    "earthlink.net": "США", "juno.com": "США", "netzero.net": "США",
    "rogers.com": "Канада", "sympatico.ca": "Канада", "shaw.ca": "Канада",
    "telus.net": "Канада", "videotron.ca": "Канада", "bell.net": "Канада",
    "cogeco.ca": "Канада", "yahoo.ca": "Канада", "hotmail.ca": "Канада",
    # Австралия и Новая Зеландия
    "bigpond.com": "Австралия", "bigpond.net.au": "Австралия",
    "optusnet.com.au": "Австралия", "iinet.net.au": "Австралия",
    "tpg.com.au": "Австралия", "yahoo.com.au": "Австралия",
    "hotmail.com.au": "Австралия", "live.com.au": "Австралия",
    "xtra.co.nz": "Новая Зеландия",
    # Азия и Латинская Америка
    "qq.com": "Китай", "foxmail.com": "Китай", "163.com": "Китай",
    "126.com": "Китай", "yeah.net": "Китай", "sina.com": "Китай",
    "naver.com": "Южная Корея", "hanmail.net": "Южная Корея", "daum.net": "Южная Корея",
    "yahoo.co.jp": "Япония", "docomo.ne.jp": "Япония", "ezweb.ne.jp": "Япония",
    "rediffmail.com": "Индия", "yahoo.co.in": "Индия",
    "uol.com.br": "Бразилия", "bol.com.br": "Бразилия", "terra.com.br": "Бразилия",
    "yahoo.com.br": "Бразилия", "yahoo.com.mx": "Мексика",
    "yahoo.com.ar": "Аргентина",
}

# TLD -> страна. Раньше карта жила внутри ml_predictor и знала 26 зон.
_TLD_COUNTRY = {
    "ru": "Россия", "su": "Россия", "рф": "Россия", "xn--p1ai": "Россия",
    "by": "Беларусь", "kz": "Казахстан", "ua": "Украина", "uz": "Узбекистан",
    "am": "Армения", "ge": "Грузия", "az": "Азербайджан", "md": "Молдова",
    "kg": "Кыргызстан", "tj": "Таджикистан", "lt": "Литва", "lv": "Латвия",
    "ee": "Эстония",
    "de": "Германия", "at": "Австрия", "ch": "Швейцария", "fr": "Франция",
    "it": "Италия", "es": "Испания", "pt": "Португалия", "nl": "Нидерланды",
    "be": "Бельгия", "lu": "Люксембург", "ie": "Ирландия", "uk": "Великобритания",
    "gb": "Великобритания", "dk": "Дания", "se": "Швеция", "no": "Норвегия",
    "fi": "Финляндия", "is": "Исландия", "pl": "Польша", "cz": "Чехия",
    "sk": "Словакия", "hu": "Венгрия", "ro": "Румыния", "bg": "Болгария",
    "gr": "Греция", "hr": "Хорватия", "si": "Словения", "rs": "Сербия",
    "ba": "Босния и Герцеговина", "mk": "Северная Македония", "al": "Албания",
    "me": "Черногория", "mt": "Мальта", "cy": "Кипр",
    "us": "США", "ca": "Канада", "mx": "Мексика", "br": "Бразилия",
    "ar": "Аргентина", "cl": "Чили", "co": "Колумбия", "pe": "Перу",
    "ve": "Венесуэла", "uy": "Уругвай", "ec": "Эквадор", "bo": "Боливия",
    "au": "Австралия", "nz": "Новая Зеландия",
    "jp": "Япония", "cn": "Китай", "hk": "Гонконг", "tw": "Тайвань",
    "kr": "Южная Корея", "in": "Индия", "pk": "Пакистан", "bd": "Бангладеш",
    "id": "Индонезия", "my": "Малайзия", "sg": "Сингапур", "th": "Таиланд",
    "vn": "Вьетнам", "ph": "Филиппины", "lk": "Шри-Ланка", "np": "Непал",
    "tr": "Турция", "il": "Израиль", "ae": "ОАЭ", "sa": "Саудовская Аравия",
    "qa": "Катар", "kw": "Кувейт", "eg": "Египет", "ma": "Марокко",
    "dz": "Алжир", "tn": "Тунис", "ir": "Иран", "iq": "Ирак", "jo": "Иордания",
    "lb": "Ливан", "za": "ЮАР", "ng": "Нигерия", "ke": "Кения", "gh": "Гана",
    "et": "Эфиопия", "tz": "Танзания", "ug": "Уганда",
}


# Как страна называется у людей -> как называем её мы. Профиль Gravatar пишет
# локацию свободным текстом («Berlin, Germany», «Москва»), и её надо узнать.
_LOCATION_HINTS = {
    "россия": "Россия", "russia": "Россия", "russian": "Россия", "москва": "Россия",
    "moscow": "Россия", "spb": "Россия", "петербург": "Россия",
    "украина": "Украина", "ukraine": "Украина", "kyiv": "Украина", "kiev": "Украина",
    "беларусь": "Беларусь", "belarus": "Беларусь", "minsk": "Беларусь",
    "kazakhstan": "Казахстан", "казахстан": "Казахстан",
    "germany": "Германия", "deutschland": "Германия", "berlin": "Германия",
    "munich": "Германия", "münchen": "Германия", "hamburg": "Германия",
    "austria": "Австрия", "vienna": "Австрия", "wien": "Австрия",
    "switzerland": "Швейцария", "zurich": "Швейцария", "geneva": "Швейцария",
    "france": "Франция", "paris": "Франция", "lyon": "Франция", "marseille": "Франция",
    "italy": "Италия", "italia": "Италия", "rome": "Италия", "roma": "Италия",
    "milan": "Италия", "milano": "Италия",
    "spain": "Испания", "españa": "Испания", "madrid": "Испания", "barcelona": "Испания",
    "portugal": "Португалия", "lisbon": "Португалия", "lisboa": "Португалия",
    "netherlands": "Нидерланды", "holland": "Нидерланды", "amsterdam": "Нидерланды",
    "belgium": "Бельгия", "brussels": "Бельгия",
    "united kingdom": "Великобритания", "england": "Великобритания",
    "scotland": "Великобритания", "wales": "Великобритания", "london": "Великобритания",
    "manchester": "Великобритания", "uk": "Великобритания",
    "ireland": "Ирландия", "dublin": "Ирландия",
    "denmark": "Дания", "copenhagen": "Дания",
    "sweden": "Швеция", "stockholm": "Швеция",
    "norway": "Норвегия", "oslo": "Норвегия",
    "finland": "Финляндия", "helsinki": "Финляндия",
    "poland": "Польша", "polska": "Польша", "warsaw": "Польша", "krakow": "Польша",
    "czech": "Чехия", "prague": "Чехия", "praha": "Чехия",
    "slovakia": "Словакия", "hungary": "Венгрия", "budapest": "Венгрия",
    "romania": "Румыния", "bucharest": "Румыния", "bulgaria": "Болгария",
    "greece": "Греция", "athens": "Греция", "croatia": "Хорватия",
    "serbia": "Сербия", "slovenia": "Словения", "turkey": "Турция",
    "istanbul": "Турция", "ankara": "Турция",
    "usa": "США", "united states": "США", "u.s.": "США", "america": "США",
    "california": "США", "new york": "США", "texas": "США", "florida": "США",
    "seattle": "США", "chicago": "США", "boston": "США", "san francisco": "США",
    "canada": "Канада", "toronto": "Канада", "vancouver": "Канада", "montreal": "Канада",
    "mexico": "Мексика", "brazil": "Бразилия", "brasil": "Бразилия",
    "são paulo": "Бразилия", "sao paulo": "Бразилия", "argentina": "Аргентина",
    "chile": "Чили", "colombia": "Колумбия", "peru": "Перу",
    "australia": "Австралия", "sydney": "Австралия", "melbourne": "Австралия",
    "new zealand": "Новая Зеландия",
    "japan": "Япония", "tokyo": "Япония", "china": "Китай", "beijing": "Китай",
    "shanghai": "Китай", "hong kong": "Гонконг", "taiwan": "Тайвань",
    "korea": "Южная Корея", "seoul": "Южная Корея",
    "india": "Индия", "mumbai": "Индия", "bangalore": "Индия", "delhi": "Индия",
    "pakistan": "Пакистан", "indonesia": "Индонезия", "singapore": "Сингапур",
    "malaysia": "Малайзия", "thailand": "Таиланд", "vietnam": "Вьетнам",
    "philippines": "Филиппины", "israel": "Израиль", "tel aviv": "Израиль",
    "uae": "ОАЭ", "dubai": "ОАЭ", "saudi": "Саудовская Аравия",
    "egypt": "Египет", "morocco": "Марокко", "nigeria": "Нигерия",
    "south africa": "ЮАР", "kenya": "Кения",
}


def country_from_location(location: str) -> str:
    """Страна из свободного текста локации Gravatar. Пусто, если не узнали.

    Сначала пробуем последний фрагмент («Berlin, Germany» — страна обычно в
    конце), потом ищем любое известное упоминание по всей строке.
    """
    if not isinstance(location, str) or not location.strip():
        return ""
    low = location.strip().lower()

    tail = low.rsplit(",", 1)[-1].strip()
    if tail in _LOCATION_HINTS:
        return _LOCATION_HINTS[tail]

    for hint, country in _LOCATION_HINTS.items():
        if hint in low:
            return country
    return ""


def country_from_domain(domain: str) -> str:
    """Страна пользователя по домену почты. Пустая строка, если сигнала нет.

    Порядок важен: сначала конкретный почтовик (web.de -> Германия), потом TLD.
    Домен точнее имени и всегда должен иметь приоритет над предсказанием по нему:
    у имени распределение по странам размазано, и Иван оказывается итальянцем.
    """
    if not isinstance(domain, str) or "." not in domain:
        return ""
    domain = domain.strip().lower().rstrip(".")

    direct = _DOMAIN_COUNTRY.get(domain)
    if direct:
        return direct

    # Составные зоны вида .co.uk / .com.au / .com.br решает предпоследний ярлык
    parts = domain.split(".")
    tld = parts[-1]
    if len(parts) >= 3 and parts[-2] in ("co", "com", "net", "org", "gov", "ac", "edu"):
        by_second = _TLD_COUNTRY.get(tld)
        if by_second:
            return by_second
    return _TLD_COUNTRY.get(tld, "")

# Образовательные и государственные зоны
_EDU_SUFFIXES = (".edu", ".ac.uk", ".edu.au", ".edu.cn", ".ac.jp", ".edu.br",
                 ".ac.in", ".edu.in", ".ac.nz", ".edu.sg", ".ac.za", ".edu.mx")
_GOV_SUFFIXES = (".gov", ".gov.uk", ".mil", ".gov.au", ".gouv.fr", ".gov.in",
                 ".gov.br", ".gov.ru")


# Бесплатные почтовики помимо «большой десятки».
#
# Зачем: раньше «бесплатный или корпоративный» решалось по 81 домену списка
# парсера плюс _PROVIDER_DOMAINS. Всё остальное считалось КОРПОРАТИВНЫМ и
# получало +5 в скоринге, которого не получает gmail.com, — а заодно для него
# зря делался HTTP-HEAD на несуществующий сайт. Ниже — те бесплатные сервисы,
# которые в прежние списки не попадали.
_FREE_MAIL_EXTRA = {
    # Международные вебмейлы
    "mail.com", "email.com", "usa.com", "consultant.com", "myself.com",
    "post.com", "europe.com", "asia.com", "iname.com", "writeme.com",
    "dr.com", "engineer.com", "cheerful.com", "techie.com", "accountant.com",
    "hushmail.com", "hush.com", "hushmail.me", "lavabit.com",
    "inbox.com", "mail2world.com", "myway.com", "excite.com", "lycos.com",
    "rocketmail.com", "ymail.com", "att.yahoo.com",
    "aim.com", "love.com", "games.com", "wow.com", "netscape.net",
    "gmx.at", "gmx.ch", "gmx.fr", "gmx.co.uk", "gmx.us", "gmx.li",
    "mail.de", "email.de", "smart-mail.de", "unitybox.de", "onlinehome.de",
    "zoho.com", "zohomail.com", "zoho.eu", "zoho.in",
    "tutanota.com", "tutanota.de", "tuta.io", "tuta.com", "tutamail.com", "keemail.me",
    "protonmail.com", "protonmail.ch", "proton.me", "pm.me",
    "fastmail.com", "fastmail.fm", "fastmail.us", "sent.com", "111mail.com",
    "posteo.de", "posteo.net", "mailbox.org", "runbox.com", "startmail.com",
    "disroot.org", "riseup.net", "autistici.org", "systemli.org",
    "mailfence.com", "ctemplar.com", "criptext.com", "kolabnow.com",
    "vivaldi.net", "firemail.de", "eclipso.de", "nubo.coop",
    # Приватные relay — за ними реальные люди, но домен именно бесплатный
    "privaterelay.appleid.com", "icloud.com", "duck.com", "mozmail.com",
    "relay.firefox.com", "simplelogin.io", "anonaddy.me", "addy.io",
    # Россия и соседи
    "rambler.ru", "lenta.ru", "autorambler.ru", "ro.ru", "myrambler.ru",
    "bk.ru", "inbox.ru", "list.ru", "internet.ru", "mail.ua",
    "ukr.net", "i.ua", "meta.ua", "bigmir.net", "tut.by", "mail.kz",
    "yandex.com", "yandex.by", "yandex.kz", "yandex.ua", "narod.ru",
    "km.ru", "pochta.ru", "nm.ru", "front.ru", "hotbox.ru", "land.ru",
    # Европа
    "seznam.cz", "email.cz", "centrum.cz", "post.cz", "atlas.cz", "volny.cz",
    "azet.sk", "zoznam.sk", "centrum.sk", "pobox.sk",
    "freemail.hu", "citromail.hu", "indamail.hu",
    "abv.bg", "dir.bg", "mail.bg",
    "wp.pl", "onet.pl", "o2.pl", "interia.pl", "gazeta.pl", "poczta.fm",
    "op.pl", "tlen.pl", "buziaczek.pl", "vp.pl", "go2.pl",
    "mail.ee", "hot.ee", "inbox.lv", "one.lv", "apollo.lv",
    "netcourrier.com", "voila.fr", "caramail.com", "cegetel.net",
    "libero.it", "email.it", "tin.it", "inwind.it", "iol.it", "supereva.it",
    "terra.es", "ya.com", "hotmail.com.es",
    "sapo.pt", "netcabo.pt", "clix.pt",
    "mail.ru.com", "email.ua",
    # Азия, Африка, Латинская Америка
    "sina.com", "sina.cn", "sohu.com", "tom.com", "21cn.com", "aliyun.com",
    "naver.com", "hanmail.net", "daum.net", "nate.com", "korea.com",
    "rediffmail.com", "sify.com", "indiatimes.com", "in.com",
    "yeah.net", "vip.163.com", "vip.126.com",
    "bol.com.br", "ig.com.br", "globo.com", "zipmail.com.br",
    "prodigy.net.mx", "latinmail.com",
    "walla.com", "walla.co.il", "nana10.co.il", "012.net.il",
    "mweb.co.za", "webmail.co.za", "vodamail.co.za",
}


def is_free_mail_domain(domain: str) -> bool:
    """True, если домен принадлежит бесплатному почтовику.

    Отдельная функция, а не проверка по одному списку: бесплатность решают
    ТРИ источника — крупные провайдеры, ISP-домены и расширенный список выше.
    """
    if not isinstance(domain, str) or not domain:
        return False
    domain = domain.strip().lower().rstrip(".")
    return (domain in _DOMAIN_TO_PROVIDER
            or domain in _ISP_DOMAINS
            or domain in _FREE_MAIL_EXTRA)


def extend_free_domains(domains) -> int:
    """Добавляет домены из авто-обновляемого списка. Возвращает число добавленных."""
    if (not domains or isinstance(domains, (str, bytes, int, float))
            or not hasattr(domains, "__iter__")):
        return 0
    before = len(_FREE_MAIL_EXTRA)
    for d in domains:
        d = (d or "").strip().lower()
        if d and "." in d and " " not in d:
            _FREE_MAIL_EXTRA.add(d)
    return len(_FREE_MAIL_EXTRA) - before


def get_free_domain_count() -> int:
    return len(_DOMAIN_TO_PROVIDER) + len(_ISP_DOMAINS) + len(_FREE_MAIL_EXTRA)


def classify_domain(email: str, mx_record: str = "") -> tuple:
    """Возвращает (provider_name, domain_type).

    provider_name: 'Gmail', 'Outlook', 'Google Workspace', 'Corporate' и т.п.
    domain_type:   'Personal' | 'ISP' | 'Education' | 'Government' | 'Corporate'
    """
    if not isinstance(email, str) or "@" not in email:
        return ("Unknown", "Unknown")

    domain = email.rsplit("@", 1)[1].lower().strip()

    # 1. Крупный бесплатный почтовик — определяем точно по домену
    provider = _DOMAIN_TO_PROVIDER.get(domain)
    if provider:
        return (provider, "Personal")

    # 2. Интернет-провайдер
    if domain in _ISP_DOMAINS:
        return ("ISP", "ISP")

    # 3. Прочий бесплатный почтовик (mail.com, zoho, rambler, seznam...).
    # Без этой ветки они считались корпоративными и получали лишние +5.
    if domain in _FREE_MAIL_EXTRA:
        return ("Free mail", "Personal")

    # 3. Образование и госструктуры — по зоне домена
    if domain.endswith(_EDU_SUFFIXES):
        return (_provider_from_mx(mx_record) or "Corporate", "Education")
    if domain.endswith(_GOV_SUFFIXES):
        return (_provider_from_mx(mx_record) or "Corporate", "Government")

    # 4. Свой домен — смотрим, на чьей почтовой инфраструктуре он сидит
    mx_provider = _provider_from_mx(mx_record)
    if mx_provider:
        return (mx_provider, "Corporate")

    return ("Corporate", "Corporate")


# Что можно проверить с текущего IP, а что требует особых условий.
# Основано на живых пробах SMTP, а не на догадках.
VERIFIABILITY = {
    # Отвечают честно любому IP
    "Gmail": "ok",
    "Yandex": "ok",
    "Proton": "ok",
    # Принимают ЛЮБОЙ адрес (catch-all на уровне протокола) — проверить нельзя ничем
    "Mail.ru": "never",
    # Нужен IP с обратным DNS (FCrDNS)
    "Yahoo": "needs_ptr",
    "AOL": "needs_ptr",
    # Нужен IP с чистой репутацией
    "Outlook": "needs_clean_ip",
    "iCloud": "needs_clean_ip",
    "GMX": "needs_clean_ip",
}

_VERDICT_LABEL = {
    "ok": "проверяется с любого IP",
    "never": "НЕ проверяется никогда (catch-all)",
    "needs_ptr": "нужен IP с PTR (FCrDNS)",
    "needs_clean_ip": "нужен IP с чистой репутацией",
    "unknown": "зависит от домена",
}


def scan_base_providers(email_sources, limit=None):
    """Считает разбивку базы по провайдерам БЕЗ единого сетевого запроса.

    Нужно, чтобы понять до запуска: какая доля базы вообще проверяема
    с текущего IP и стоит ли вкладываться в прокси с PTR.

    Возвращает dict: {'total', 'providers', 'verifiability'}
    """
    if (not email_sources or isinstance(email_sources, (str, bytes, dict))
            or not hasattr(email_sources, "__iter__")):
        return {"total": 0, "providers": Counter(), "verifiability": Counter()}

    from core.streamer import StreamLoader

    providers = Counter()
    verdicts = Counter()
    total = 0

    for email, _ in StreamLoader(email_sources).stream_emails():
        if not email or "@" not in email:
            continue
        total += 1
        prov, _dom_type = classify_domain(email)
        providers[prov] += 1
        verdicts[VERIFIABILITY.get(prov, "unknown")] += 1
        if limit and total >= limit:
            break

    return {"total": total, "providers": providers, "verifiability": verdicts}


def format_base_scan(scan) -> list:
    """Готовит человекочитаемый отчёт по результату scan_base_providers()."""
    if not isinstance(scan, dict):
        return ["[INFO] Скан базы: данных нет."]
    total = scan.get("total", 0)
    if not total:
        return ["[INFO] Скан базы: адресов не найдено."]

    lines = [f"[INFO] === Состав базы: {total} адресов ==="]

    for prov, cnt in scan["providers"].most_common(12):
        pct = round(cnt * 100 / total, 1)
        note = _VERDICT_LABEL.get(VERIFIABILITY.get(prov, "unknown"), "")
        lines.append(f"[INFO]   {prov:<18} {cnt:>7}  ({pct:>5}%)  — {note}")

    v = scan["verifiability"]
    ok = v.get("ok", 0)
    never = v.get("never", 0)
    ptr = v.get("needs_ptr", 0)
    clean = v.get("needs_clean_ip", 0)
    unk = v.get("unknown", 0)

    def pct(n):
        return round(n * 100 / total, 1)

    lines.append("[INFO] --- Что это значит ---")
    lines.append(f"[INFO]   Проверю с текущего IP:        {ok + unk:>7} ({pct(ok + unk)}%)")
    lines.append(f"[INFO]   Нужен IP с чистой репутацией: {clean:>7} ({pct(clean)}%)")
    lines.append(f"[INFO]   Нужен IP с PTR (Yahoo/AOL):   {ptr:>7} ({pct(ptr)}%)")
    lines.append(f"[INFO]   Не проверяется никогда:       {never:>7} ({pct(never)}%)")

    gain = clean + ptr
    if gain == 0:
        lines.append("[INFO] Вывод: VPS с PTR ничего не добавит — таких адресов в базе нет.")
    elif pct(gain) < 10:
        lines.append(f"[INFO] Вывод: VPS с PTR добавит лишь {pct(gain)}% базы. Вероятно, не окупится.")
    else:
        lines.append(f"[INFO] Вывод: VPS с чистым IP и PTR откроет {gain} адресов ({pct(gain)}% базы).")

    return lines


def _provider_from_mx(mx_record: str):
    """Определяет хостера почты по MX-записи."""
    if not isinstance(mx_record, str) or not mx_record or mx_record == "N/A":
        return None
    mx = mx_record.lower()
    for hint, name in _MX_PROVIDER_HINTS.items():
        if hint in mx:
            return name
    return None
