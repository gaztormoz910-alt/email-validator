import time
from collections import Counter

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

_DOMAIN_TO_PROVIDER = {}
for _prov, _domains in _PROVIDER_DOMAINS.items():
    for _d in _domains:
        _DOMAIN_TO_PROVIDER[_d] = _prov

_ISP_DOMAINS = {
    "comcast.net", "verizon.net", "att.net", "sbcglobal.net", "bellsouth.net",
    "cox.net", "charter.net", "earthlink.net", "juno.com", "netzero.net",
    "optonline.net", "roadrunner.com", "rr.com", "windstream.net", "frontier.com",
    "centurylink.net", "embarqmail.com", "shaw.ca", "rogers.com", "sympatico.ca",
    "telus.net", "bigpond.com", "optusnet.com.au", "virginmedia.com", "sky.com",
    "btinternet.com", "talktalk.net", "orange.fr", "wanadoo.fr", "free.fr",
    "t-online.de", "web.de", "libero.it", "terra.com.br", "uol.com.br",
}

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

_DOMAIN_COUNTRY = {
    "web.de": "Германия", "gmx.de": "Германия", "gmx.net": "Германия",
    "t-online.de": "Германия", "freenet.de": "Германия", "hotmail.de": "Германия",
    "yahoo.de": "Германия", "outlook.de": "Германия", "arcor.de": "Германия",
    "1und1.de": "Германия", "posteo.de": "Германия", "mailbox.org": "Германия",
    "orange.fr": "Франция", "free.fr": "Франция", "sfr.fr": "Франция",
    "laposte.net": "Франция", "wanadoo.fr": "Франция", "yahoo.fr": "Франция",
    "hotmail.fr": "Франция", "bbox.fr": "Франция", "neuf.fr": "Франция",
    "numericable.fr": "Франция", "aliceadsl.fr": "Франция",
    "libero.it": "Италия", "virgilio.it": "Италия", "tim.it": "Италия",
    "alice.it": "Италия", "tiscali.it": "Италия", "yahoo.it": "Италия",
    "hotmail.it": "Италия", "email.it": "Италия", "inwind.it": "Италия",
    "fastwebnet.it": "Италия", "poste.it": "Италия",
    "yahoo.es": "Испания", "hotmail.es": "Испания", "telefonica.net": "Испания",
    "terra.es": "Испания", "movistar.es": "Испания",
    "btinternet.com": "Великобритания", "sky.com": "Великобритания",
    "virginmedia.com": "Великобритания", "talktalk.net": "Великобритания",
    "blueyonder.co.uk": "Великобритания", "ntlworld.com": "Великобритания",
    "hotmail.co.uk": "Великобритания", "yahoo.co.uk": "Великобритания",
    "live.co.uk": "Великобритания", "outlook.co.uk": "Великобритания",
    "virgin.net": "Великобритания", "tiscali.co.uk": "Великобритания",
    "ziggo.nl": "Нидерланды", "kpnmail.nl": "Нидерланды", "planet.nl": "Нидерланды",
    "hetnet.nl": "Нидерланды", "upcmail.nl": "Нидерланды", "chello.nl": "Нидерланды",
    "xs4all.nl": "Нидерланды", "hotmail.nl": "Нидерланды", "live.nl": "Нидерланды",
    "telenet.be": "Бельгия", "skynet.be": "Бельгия", "proximus.be": "Бельгия",
    "wp.pl": "Польша", "onet.pl": "Польша", "o2.pl": "Польша",
    "interia.pl": "Польша", "gazeta.pl": "Польша", "poczta.onet.pl": "Польша",
    "mail.ru": "Россия", "bk.ru": "Россия", "inbox.ru": "Россия",
    "list.ru": "Россия", "internet.ru": "Россия", "yandex.ru": "Россия",
    "ya.ru": "Россия", "rambler.ru": "Россия", "lenta.ru": "Россия",
    "autorambler.ru": "Россия", "bushmail.ru": "Россия",
    "ukr.net": "Украина", "i.ua": "Украина", "meta.ua": "Украина",
    "tut.by": "Беларусь", "yandex.by": "Беларусь",
    "yandex.kz": "Казахстан", "mail.kz": "Казахстан",
    "telia.com": "Швеция", "bredband.net": "Швеция", "spray.se": "Швеция",
    "online.no": "Норвегия", "broadpark.no": "Норвегия",
    "sol.dk": "Дания", "mail.dk": "Дания",
    "luukku.com": "Финляндия", "suomi24.fi": "Финляндия",
    "comcast.net": "США", "sbcglobal.net": "США", "att.net": "США",
    "verizon.net": "США", "cox.net": "США", "charter.net": "США",
    "bellsouth.net": "США", "optonline.net": "США", "roadrunner.com": "США",
    "windstream.net": "США", "frontier.com": "США", "centurylink.net": "США",
    "earthlink.net": "США", "juno.com": "США", "netzero.net": "США",
    "rogers.com": "Канада", "sympatico.ca": "Канада", "shaw.ca": "Канада",
    "telus.net": "Канада", "videotron.ca": "Канада", "bell.net": "Канада",
    "cogeco.ca": "Канада", "yahoo.ca": "Канада", "hotmail.ca": "Канада",
    "bigpond.com": "Австралия", "bigpond.net.au": "Австралия",
    "optusnet.com.au": "Австралия", "iinet.net.au": "Австралия",
    "tpg.com.au": "Австралия", "yahoo.com.au": "Австралия",
    "hotmail.com.au": "Австралия", "live.com.au": "Австралия",
    "xtra.co.nz": "Новая Зеландия",
    "qq.com": "Китай", "foxmail.com": "Китай", "163.com": "Китай",
    "126.com": "Китай", "yeah.net": "Китай", "sina.com": "Китай",
    "naver.com": "Южная Корея", "hanmail.net": "Южная Корея", "daum.net": "Южная Корея",
    "yahoo.co.jp": "Япония", "docomo.ne.jp": "Япония", "ezweb.ne.jp": "Япония",
    "rediffmail.com": "Индия", "yahoo.co.in": "Индия",
    "uol.com.br": "Бразилия", "bol.com.br": "Бразилия", "terra.com.br": "Бразилия",
    "yahoo.com.br": "Бразилия", "yahoo.com.mx": "Мексика",
    "yahoo.com.ar": "Аргентина",
}

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


_СТРАНЫ_ПО_ИМЕНИ = {
    "afghanistan": "Афганистан", "albania": "Албания", "algeria": "Алжир",
    "andorra": "Андорра", "angola": "Ангола", "armenia": "Армения",
    "azerbaijan": "Азербайджан", "bahamas": "Багамы", "bahrain": "Бахрейн",
    "bangladesh": "Бангладеш", "barbados": "Барбадос", "belize": "Белиз",
    "benin": "Бенин", "bhutan": "Бутан", "bolivia": "Боливия",
    "bosnia": "Босния и Герцеговина", "botswana": "Ботсвана",
    "brunei": "Бруней", "burkina faso": "Буркина-Фасо", "burundi": "Бурунди",
    "cambodia": "Камбоджа", "cameroon": "Камерун", "chad": "Чад",
    "comoros": "Коморы", "congo": "Конго", "costa rica": "Коста-Рика",
    "cuba": "Куба", "cyprus": "Кипр", "czech republic": "Чехия",
    "czechia": "Чехия", "djibouti": "Джибути", "dominica": "Доминика",
    "dominican republic": "Доминиканская Республика", "ecuador": "Эквадор",
    "el salvador": "Сальвадор", "eritrea": "Эритрея", "estonia": "Эстония",
    "ethiopia": "Эфиопия", "fiji": "Фиджи", "gabon": "Габон",
    "gambia": "Гамбия", "georgia": "Грузия", "ghana": "Гана",
    "great britain": "Великобритания", "grenada": "Гренада",
    "guatemala": "Гватемала", "guinea": "Гвинея", "guyana": "Гайана",
    "haiti": "Гаити", "honduras": "Гондурас", "iceland": "Исландия",
    "iran": "Иран", "iraq": "Ирак", "jamaica": "Ямайка",
    "jordan": "Иордания", "kiribati": "Кирибати", "korea": "Южная Корея",
    "kuwait": "Кувейт", "kyrgyzstan": "Кыргызстан", "laos": "Лаос",
    "latvia": "Латвия", "lebanon": "Ливан", "lesotho": "Лесото",
    "liberia": "Либерия", "libya": "Ливия", "liechtenstein": "Лихтенштейн",
    "lithuania": "Литва", "luxembourg": "Люксембург", "macao": "Макао",
    "macau": "Макао", "madagascar": "Мадагаскар", "malawi": "Малави",
    "maldives": "Мальдивы", "mali": "Мали", "malta": "Мальта",
    "mauritania": "Мавритания", "mauritius": "Маврикий", "moldova": "Молдова",
    "monaco": "Монако", "mongolia": "Монголия", "montenegro": "Черногория",
    "mozambique": "Мозамбик", "myanmar": "Мьянма", "namibia": "Намибия",
    "nauru": "Науру", "nepal": "Непал", "nicaragua": "Никарагуа",
    "niger": "Нигер", "north korea": "Северная Корея", "oman": "Оман",
    "palau": "Палау", "panama": "Панама",
    "papua new guinea": "Папуа — Новая Гвинея", "paraguay": "Парагвай",
    "puerto rico": "Пуэрто-Рико", "qatar": "Катар",
    "russian federation": "Россия", "rwanda": "Руанда", "samoa": "Самоа",
    "saudi arabia": "Саудовская Аравия", "senegal": "Сенегал",
    "seychelles": "Сейшелы", "sierra leone": "Сьерра-Леоне",
    "somalia": "Сомали", "south korea": "Южная Корея",
    "sri lanka": "Шри-Ланка", "sudan": "Судан", "suriname": "Суринам",
    "syria": "Сирия", "tajikistan": "Таджикистан", "tanzania": "Танзания",
    "togo": "Того", "tonga": "Тонга", "trinidad": "Тринидад и Тобаго",
    "trinidad and tobago": "Тринидад и Тобаго", "tunisia": "Тунис",
    "turkiye": "Турция", "türkiye": "Турция",
    "turkmenistan": "Туркменистан", "tuvalu": "Тувалу", "uganda": "Уганда",
    "united arab emirates": "ОАЭ",
    "united states of america": "США", "u.s.a.": "США",
    "uruguay": "Уругвай", "uzbekistan": "Узбекистан", "vanuatu": "Вануату",
    "venezuela": "Венесуэла", "viet nam": "Вьетнам", "yemen": "Йемен",
    "zambia": "Замбия", "zimbabwe": "Зимбабве",
    "австралия": "Австралия", "австрия": "Австрия",
    "азербайджан": "Азербайджан", "алжир": "Алжир", "аргентина": "Аргентина",
    "армения": "Армения", "бангладеш": "Бангладеш", "бельгия": "Бельгия",
    "болгария": "Болгария", "бразилия": "Бразилия",
    "великобритания": "Великобритания", "венгрия": "Венгрия",
    "венесуэла": "Венесуэла", "вьетнам": "Вьетнам", "германия": "Германия",
    "греция": "Греция", "грузия": "Грузия", "дания": "Дания",
    "египет": "Египет", "израиль": "Израиль", "индия": "Индия",
    "индонезия": "Индонезия", "ирак": "Ирак", "иран": "Иран",
    "ирландия": "Ирландия", "исландия": "Исландия", "испания": "Испания",
    "италия": "Италия", "канада": "Канада", "кения": "Кения",
    "кипр": "Кипр", "китай": "Китай", "колумбия": "Колумбия",
    "куба": "Куба", "кыргызстан": "Кыргызстан", "латвия": "Латвия",
    "ливия": "Ливия", "литва": "Литва", "люксембург": "Люксембург",
    "малайзия": "Малайзия", "мальта": "Мальта", "марокко": "Марокко",
    "мексика": "Мексика", "молдова": "Молдова", "монако": "Монако",
    "непал": "Непал", "нигерия": "Нигерия", "нидерланды": "Нидерланды",
    "норвегия": "Норвегия", "оаэ": "ОАЭ", "пакистан": "Пакистан",
    "перу": "Перу", "польша": "Польша", "португалия": "Португалия",
    "румыния": "Румыния", "саудовская аравия": "Саудовская Аравия",
    "сербия": "Сербия", "сингапур": "Сингапур", "словакия": "Словакия",
    "словения": "Словения", "сша": "США", "таджикистан": "Таджикистан",
    "таиланд": "Таиланд", "тунис": "Тунис", "туркменистан": "Туркменистан",
    "турция": "Турция", "узбекистан": "Узбекистан", "филиппины": "Филиппины",
    "финляндия": "Финляндия", "франция": "Франция", "хорватия": "Хорватия",
    "чехия": "Чехия", "чили": "Чили", "швейцария": "Швейцария",
    "швеция": "Швеция", "эстония": "Эстония", "юар": "ЮАР",
    "южная корея": "Южная Корея", "япония": "Япония",
}

_КОД_ISO_ДОП = {
    "ad": "Андорра", "af": "Афганистан", "ao": "Ангола", "bb": "Барбадос",
    "bf": "Буркина-Фасо", "bh": "Бахрейн", "bi": "Бурунди", "bj": "Бенин",
    "bn": "Бруней", "bs": "Багамы", "bt": "Бутан", "bw": "Ботсвана",
    "bz": "Белиз", "cg": "Конго", "cm": "Камерун", "cr": "Коста-Рика",
    "cu": "Куба", "dj": "Джибути", "dm": "Доминика",
    "do": "Доминиканская Республика", "er": "Эритрея", "fj": "Фиджи",
    "ga": "Габон", "gd": "Гренада", "gm": "Гамбия", "gn": "Гвинея",
    "gt": "Гватемала", "gy": "Гайана", "hn": "Гондурас", "ht": "Гаити",
    "jm": "Ямайка", "kh": "Камбоджа", "ki": "Кирибати", "km": "Коморы",
    "la": "Лаос", "li": "Лихтенштейн", "lr": "Либерия", "ls": "Лесото",
    "ly": "Ливия", "mc": "Монако", "mg": "Мадагаскар", "ml": "Мали",
    "mm": "Мьянма", "mn": "Монголия", "mr": "Мавритания", "mu": "Маврикий",
    "mv": "Мальдивы", "mw": "Малави", "mz": "Мозамбик", "na": "Намибия",
    "ne": "Нигер", "ni": "Никарагуа", "nr": "Науру", "om": "Оман",
    "pa": "Панама", "pg": "Папуа — Новая Гвинея", "pw": "Палау",
    "py": "Парагвай", "rw": "Руанда", "sc": "Сейшелы", "sd": "Судан",
    "sl": "Сьерра-Леоне", "sn": "Сенегал", "so": "Сомали", "sr": "Суринам",
    "sv": "Сальвадор", "sy": "Сирия", "td": "Чад", "tg": "Того",
    "tm": "Туркменистан", "to": "Тонга", "tt": "Тринидад и Тобаго",
    "tv": "Тувалу", "vu": "Вануату", "ws": "Самоа", "ye": "Йемен",
    "zm": "Замбия", "zw": "Зимбабве",
}

_КОД_СТРАНЫ = dict(_КОД_ISO_ДОП)
_КОД_СТРАНЫ.update({код: имя for код, имя in _TLD_COUNTRY.items()
                    if len(код) == 2})


_КАНОНИЧЕСКИЕ_СТРАНЫ = (frozenset(_СТРАНЫ_ПО_ИМЕНИ.values())
                        | frozenset(_LOCATION_HINTS.values())
                        | frozenset(_TLD_COUNTRY.values())
                        | frozenset(_DOMAIN_COUNTRY.values())
                        | frozenset(_КОД_ISO_ДОП.values()))

def canonical_country(value: str) -> str:
    if not isinstance(value, str):
        return ""
    ячейка = value.strip()
    if not ячейка:
        return ""
    низ = ячейка.lower()
    known = _СТРАНЫ_ПО_ИМЕНИ.get(низ) or _LOCATION_HINTS.get(низ)
    if known:
        return known
    if len(низ) == 2:
        known = _КОД_СТРАНЫ.get(низ)
        if known:
            return known
    return ячейка


def country_is_known(value) -> bool:
    if not isinstance(value, str):
        return False
    низ = value.strip().lower()
    if not низ:
        return False
    return (низ in _СТРАНЫ_ПО_ИМЕНИ or низ in _LOCATION_HINTS
            or (len(низ) == 2 and низ in _КОД_СТРАНЫ)
            or value.strip() in _КАНОНИЧЕСКИЕ_СТРАНЫ)


_МУЖСКИЕ = {"male", "m", "man", "boy", "мужской", "муж", "мужчина", "мужик",
            "мужч", "mostly_male", "мужской пол", "мужск"}
_ЖЕНСКИЕ = {"female", "f", "woman", "girl", "женский", "жен", "женщина",
            "женск", "mostly_female", "женский пол"}
_ПОЛ_НЕИЗВЕСТЕН = {"unknown", "andy", "n/a", "na", "none", "null", "-", "?",
                   "unisex", "other", "неизвестно", "не указан"}


def canonical_gender(value: str) -> str:
    if not isinstance(value, str):
        return ""
    ячейка = value.strip()
    if not ячейка:
        return ""
    низ = ячейка.lower()
    if низ in _МУЖСКИЕ:
        return "Мужской"
    if низ in _ЖЕНСКИЕ:
        return "Женский"
    if низ in _ПОЛ_НЕИЗВЕСТЕН:
        return ""
    return ячейка


def country_from_domain(domain: str) -> str:
    if not isinstance(domain, str) or "." not in domain:
        return ""
    domain = domain.strip().lower().rstrip(".")

    direct = _DOMAIN_COUNTRY.get(domain)
    if direct:
        return direct

    parts = domain.split(".")
    tld = parts[-1]
    if len(parts) >= 3 and parts[-2] in ("co", "com", "net", "org", "gov", "ac", "edu"):
        by_second = _TLD_COUNTRY.get(tld)
        if by_second:
            return by_second
    return _TLD_COUNTRY.get(tld, "")

_EDU_SUFFIXES = (".edu", ".ac.uk", ".edu.au", ".edu.cn", ".ac.jp", ".edu.br",
                 ".ac.in", ".edu.in", ".ac.nz", ".edu.sg", ".ac.za", ".edu.mx")
_GOV_SUFFIXES = (".gov", ".gov.uk", ".mil", ".gov.au", ".gouv.fr", ".gov.in",
                 ".gov.br", ".gov.ru")


_FREE_MAIL_EXTRA = {
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
    "privaterelay.appleid.com", "icloud.com", "duck.com", "mozmail.com",
    "relay.firefox.com", "simplelogin.io", "anonaddy.me", "addy.io",
    "rambler.ru", "lenta.ru", "autorambler.ru", "ro.ru", "myrambler.ru",
    "bk.ru", "inbox.ru", "list.ru", "internet.ru", "mail.ua",
    "ukr.net", "i.ua", "meta.ua", "bigmir.net", "tut.by", "mail.kz",
    "yandex.com", "yandex.by", "yandex.kz", "yandex.ua", "narod.ru",
    "km.ru", "pochta.ru", "nm.ru", "front.ru", "hotbox.ru", "land.ru",
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
    if not isinstance(domain, str) or not domain:
        return False
    domain = domain.strip().lower().rstrip(".")
    return (domain in _DOMAIN_TO_PROVIDER
            or domain in _ISP_DOMAINS
            or domain in _FREE_MAIL_EXTRA)


def extend_free_domains(domains) -> int:
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
    if not isinstance(email, str) or "@" not in email:
        return ("Unknown", "Unknown")

    domain = email.rsplit("@", 1)[1].lower().strip()

    provider = _DOMAIN_TO_PROVIDER.get(domain)
    if provider:
        return (provider, "Personal")

    if domain in _ISP_DOMAINS:
        return ("ISP", "ISP")

    if domain in _FREE_MAIL_EXTRA:
        return ("Free mail", "Personal")

    if domain.endswith(_EDU_SUFFIXES):
        return (_provider_from_mx(mx_record) or "Corporate", "Education")
    if domain.endswith(_GOV_SUFFIXES):
        return (_provider_from_mx(mx_record) or "Corporate", "Government")

    mx_provider = _provider_from_mx(mx_record)
    if mx_provider:
        return (mx_provider, "Corporate")

    return ("Corporate", "Corporate")


VERIFIABILITY = {
    "Gmail": "ok",
    "Yandex": "ok",
    "Proton": "ok",
    "Mail.ru": "never",
    "Yahoo": "needs_ptr",
    "AOL": "needs_ptr",
    "Outlook": "needs_clean_ip",
    "iCloud": "needs_clean_ip",
    "GMX": "needs_clean_ip",
}

_ПРИОРИТЕТ_ПРОВЕРЯЕМОСТИ = {
    "ok": 5,
    "needs_clean_ip": 4,
    "needs_ptr": 3,
    "never": 0,
}
_ПРИОРИТЕТ_ТИПА = {"ISP": 2, "Personal": 2}


def address_priority(email: str) -> int:
    if not isinstance(email, str) or "@" not in email:
        return -1
    провайдер, тип_домена = classify_domain(email)
    известность = VERIFIABILITY.get(провайдер)
    if известность is not None:
        return _ПРИОРИТЕТ_ПРОВЕРЯЕМОСТИ.get(известность, 1)
    return _ПРИОРИТЕТ_ТИПА.get(тип_домена, 1)


def best_address(addresses):
    if not isinstance(addresses, (list, tuple, set)):
        return ""
    лучший = ""
    лучший_балл = -2
    for адрес in addresses:
        if not isinstance(адрес, str) or "@" not in адрес:
            continue
        балл = address_priority(адрес)
        if балл > лучший_балл:
            лучший, лучший_балл = адрес, балл
    return лучший


_VERDICT_LABEL = {
    "ok": "проверяется с любого IP",
    "never": "НЕ проверяется никогда (catch-all)",
    "needs_ptr": "нужен IP с PTR (FCrDNS)",
    "needs_clean_ip": "нужен IP с чистой репутацией",
    "unknown": "зависит от домена",
}


BASE_SCAN_BREATHE = 1000


def scan_base_providers(email_sources, limit=None, breathe_every=0,
                        should_stop=None, on_row=None):
    if (not email_sources or isinstance(email_sources, (str, bytes, dict))
            or not hasattr(email_sources, "__iter__")):
        return {"total": 0, "providers": Counter(), "verifiability": Counter()}

    from core.streamer import StreamLoader

    providers = Counter()
    verdicts = Counter()
    total = 0
    try:
        breathe_every = int(breathe_every or 0)
    except (TypeError, ValueError):
        breathe_every = 0

    for email, data in StreamLoader(email_sources).stream_emails():
        if not email or "@" not in email:
            continue
        if on_row is not None:
            on_row(email, data)
        total += 1
        prov, _dom_type = classify_domain(email)
        providers[prov] += 1
        verdicts[VERIFIABILITY.get(prov, "unknown")] += 1
        if breathe_every > 0 and total % breathe_every == 0:
            if should_stop is not None:
                try:
                    if should_stop():
                        return {"total": total, "providers": providers,
                                "verifiability": verdicts, "stopped": True}
                except Exception:
                    pass
            time.sleep(0.001)
        if limit and total >= limit:
            break

    return {"total": total, "providers": providers, "verifiability": verdicts}


def format_base_scan(scan) -> list:
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
    if not isinstance(mx_record, str) or not mx_record or mx_record == "N/A":
        return None
    mx = mx_record.lower()
    for hint, name in _MX_PROVIDER_HINTS.items():
        if hint in mx:
            return name
    return None
