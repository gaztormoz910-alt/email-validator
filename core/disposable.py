# core/disposable.py
"""
Детектор одноразовых/временных почтовых сервисов.
Проверяет домен email по списку 3000+ известных disposable-провайдеров.
"""

# Огромный список одноразовых почтовых доменов (disposable/temporary email providers)
# Источник: github.com/disposable-email-domains + ручные дополнения
DISPOSABLE_DOMAINS = {
    # Самые популярные одноразовые сервисы
    "guerrillamail.com", "guerrillamail.info", "guerrillamail.net", "guerrillamail.org",
    "guerrillamail.de", "guerrilla.ml", "grr.la",
    "tempmail.com", "temp-mail.org", "temp-mail.io", "temp-mail.ru",
    "tempmail.plus", "tempmail.ninja", "tempmail.de", "tempmail.it",
    "mailinator.com", "mailinator.net", "mailinator2.com",
    "maildrop.cc", "maildrop.ml",
    "throwaway.email", "throwawaymail.com",
    "yopmail.com", "yopmail.fr", "yopmail.net", "yopmail.gq",
    "dispostable.com", "disposableemailaddresses.emailmiser.com",
    "sharklasers.com", "guerrillamailblock.com", "pokemail.net", "spam4.me",
    "trashmail.com", "trashmail.me", "trashmail.net", "trashmail.org", "trashmail.io",
    "trashmail.at", "trashmail.de",
    "10minutemail.com", "10minutemail.net", "10minutemail.org", "10minutemail.co.za",
    "10minute.email",
    "minutemail.com",
    "fakeinbox.com", "fakemail.net", "fakemailgenerator.com",
    "mailnesia.com", "mailnull.com",
    "tempr.email", "tempinbox.com", "tempail.com",
    "getnada.com", "nada.email", "nada.ltd",
    "mohmal.com", "mohmal.in", "mohmal.im",
    "emailondeck.com",
    "crazymailing.com",
    "discard.email", "discardmail.com", "discardmail.de",
    "mailcatch.com",
    "inboxbear.com",
    "harakirimail.com",
    "mailhazard.com", "mailhazard.us",
    "guerrillamailblock.com",
    "imgof.com",
    "jetable.com", "jetable.fr.nf", "jetable.net", "jetable.org",
    "mailexpire.com",
    "mailmoat.com",
    "mailshell.com",
    "mailzilla.com", "mailzilla.org",
    "nomail.xl.cx",
    "objectmail.com",
    "obobbo.com",
    "onewaymail.com",
    "proxymail.eu",
    "rcpt.at",
    "reallymymail.com",
    "recode.me",
    "regbypass.com",
    "safetymail.info",
    "short.email",
    "shitmail.me", "shitmail.org",
    "spamavert.com",
    "spambox.us",
    "spamfree24.org",
    "spamgourmet.com", "spamgourmet.net", "spamgourmet.org",
    "spamhereplease.com",
    "spamhole.com",
    "spaml.de", "spaml.com",
    "spammotel.com",
    "spamspot.com",
    "tempomail.fr",
    "temporaryemail.net", "temporaryemail.us",
    "temporarymailaddress.com",
    "thankdog.net",
    "thejoker5.com",
    "tmpmail.net", "tmpmail.org",
    "trash-mail.at", "trash-mail.com", "trash-mail.de",
    "trashdevil.com", "trashdevil.de",
    "trbvm.com", "trbvn.com",
    "uggsrock.com",
    "veryreallyfakeaddress.com",
    "wegwerfmail.de", "wegwerfmail.net", "wegwerfmail.org",
    "wh4f.org",
    "willhackforfood.biz",
    "xagloo.com",
    "yep.it",
    "yogamaven.com",
    "zehnminuten.de",
    "zehnminutenmail.de",
    "zoemail.net", "zoemail.org",
    # Mailnator variants
    "binkmail.com", "bobmail.info", "chammy.info", "devnullmail.com",
    "letthemeatspam.com", "mailismagic.com", "mailmetrash.com",
    "nothingtoseehere.ca", "putthisinyouremail.com", "safetypost.de",
    "spamfighter.cf", "spamfighter.ga", "spamfighter.gq", "spamfighter.ml",
    "spamfighter.tk",
    # Guerrilla Mail variants
    "grr.la", "guerrillamail.biz",
    # Russian disposable services
    "crapmail.org", "dandikmail.com", "dayrep.com",
    "einrot.com", "emailigo.de", "emailisvalid.com",
    "emailsensei.com", "emailtemporario.com.br",
    "ephemail.net", "etranquil.com", "etranquil.net", "etranquil.org",
    "evopo.com",
    "eyepaste.com",
    "fleckens.hu", "flemail.ru",
    "get1mail.com", "get2mail.fr",
    "getairmail.com",
    "getonemail.com", "getonemail.net",
    "gishpuppy.com",
    "giurl.com",
    "great-host.in",
    "greensloth.com",
    "haltospam.com", "hatespam.org",
    "hidemail.de",
    "hidzz.com",
    "hotpop.com",
    "hulapla.de",
    "ieh-mail.de",
    "imails.info",
    "inboxalias.com",
    "inboxclean.com", "inboxclean.org",
    "incognitomail.com", "incognitomail.net", "incognitomail.org",
    "insorg-mail.info",
    "ipoo.org",
    "irish2me.com",
    "iwi.net",
    "jetable.com",
    "kasmail.com",
    "kaspop.com",
    "keepmymail.com",
    "killmail.com", "killmail.net",
    "kingsq.ga",
    "klassmaster.com", "klassmaster.net",
    "klzlk.com",
    "koszmail.pl",
    "kurzepost.de",
    "lawlita.com",
    "letthemeatspam.com",
    "lhsdv.com",
    "lifebyfood.com",
    "link2mail.net",
    "litedrop.com",
    "lol.ovpn.to",
    "lookugly.com",
    "lortemail.dk",
    "lr78.com",
    "m4ilweb.info",
    "maileater.com",
    "mailexpire.com",
    "mailforspam.com",
    "mailfree.ga", "mailfree.gq", "mailfree.ml",
    "mailimate.com",
    "mailinator.org", "mailinator.us",
    "mailme.ir", "mailme.lv",
    "mailmetrash.com",
    "mailnator.com",
    "mailnull.com",
    "mailsac.com",
    "mailscrap.com",
    "mailseal.de",
    "mailshell.com",
    "mailsiphon.com",
    "mailslite.com",
    "mailtemp.info",
    "mailtothis.com",
    "mailtrash.net",
    "mailzilla.com",
    "makemetheking.com",
    "manifestgenerator.com",
    "messagebeamer.de",
    "mezimages.net",
    "ministry-of-silly-walks.de",
    "mintemail.com",
    "mjukgansen.com",
    "mobi.web.id",
    "moburl.com",
    "moncourrier.fr.nf",
    "monemail.fr.nf",
    "monmail.fr.nf",
    "mt2015.com",
    "mx0.wwwnew.eu",
    "mypartyclip.de",
    "myphantom.com",
    "mysamp.de",
    "mytempemail.com",
    "mytempmail.com",
    "mytrashmail.com",
    "nabala.com",
    "neverbox.com",
    "no-spam.ws",
    "nobulk.com", "noclickemail.com",
    "nogmailspam.info",
    "nomail.pw", "nomail.xl.cx", "nomail2me.com",
    "nomorespamemails.com",
    "nospam.ze.tc", "nospam4.us",
    "nospamfor.us", "nospammail.net", "nospamthanks.info",
    "nothingtoseehere.ca",
    "nowmymail.com",
    "nurfuerspam.de",

    "nwldx.com",
    "objectmail.com",
    "obobbo.com",
    "odnorazovoe.ru",
    "oneoffemail.com", "oneoffmail.com",
    "onewaymail.com",
    "oopi.org",
    "ordinaryamerican.net",
    "owlpic.com",
    "pancakemail.com",
    "pjjkp.com",
    "plexolan.de",

    "politikerclub.de",
    "poofy.org",
    "pookmail.com",
    "privacy.net",
    "prtnx.com",
    "putthisinyouremail.com",
    "qq.com.trash", "quickinbox.com",
    "rcpt.at",
    "reallymymail.com",
    "recode.me",
    "recursor.net",
    "regbypass.com",
    "rhyta.com",
    "rklips.com",
    "rmqkr.net",
    "royal.net",
    "rppkn.com",
    "rtrtr.com",
    "s0ny.net",
    "safe-mail.net",
    "safersignup.de",
    "safetymail.info",
    "sandelf.de",
    "saynotospams.com",
    "scatmail.com",
    "schafmail.de",
    "selfdestructingmail.com",
    "sendspamhere.com",
    "shieldedmail.com",
    "shiftmail.com",
    "shitmail.me",
    "shortmail.net",
    "sibmail.com",
    "skeefmail.com",
    "slaskpost.se",
    "slipry.net",
    "slopsbox.com",
    "slowslow.de",
    "smashmail.de",
    "smellfear.com",
    "snakemail.com",
    "sneakemail.com",
    "snkmail.com",
    "sofimail.com",
    "sofort-mail.de",
    "softpls.asia",
    "sogetthis.com",
    "soodonims.com",
    "spam.la", "spam.su", "spam4.me",
    "spamavert.com",
    "spambob.com", "spambob.net", "spambob.org",
    "spambog.com", "spambog.de", "spambog.ru",
    "spambox.info", "spambox.irishspringrealty.com", "spambox.us",
    "spamcannon.com", "spamcannon.net",
    "spamcero.com",
    "spamcon.org",
    "spamcorptastic.com",
    "spamcowboy.com", "spamcowboy.net", "spamcowboy.org",
    "spamday.com",
    "spamex.com",
    "spamfree.eu", "spamfree24.com", "spamfree24.de", "spamfree24.eu",
    "spamfree24.info", "spamfree24.net", "spamfree24.org",
    "spamgoes.in",
    "spamherelots.com",
    "spamhereplease.com",
    "spamhole.com",
    "spamify.com",
    "spaminator.de",
    "spamkill.info",
    "spaml.com", "spaml.de",
    "spammotel.com",
    "spamobox.com",
    "spamoff.de",
    "spamslicer.com",
    "spamspot.com",
    "spamstack.net",
    "spamthis.co.uk",
    "spamthisplease.com",
    "spamtrail.com",
    "spamtrap.ro",
    "speed.1s.fr",
    "spoofmail.de",
    "squizzy.de",
    "sry.li",
    "stinkefinger.net",
    "stuffmail.de",
    "supergreatmail.com",
    "supermailer.jp",
    "superrito.com",
    "superstachel.de",
    "suremail.info",
    "svk.jp",
    "sweetxxx.de",
    "tafmail.com",
    "tagyoureit.com",
    "talkinator.com",
    "tapchicuoihoi.com",
    "teewars.org",
    "teleworm.com", "teleworm.us",
    "temp.emeraldcraft.com",
    "temp.headstrong.de",
    "tempalias.com",
    "tempe4mail.com",
    "tempemail.biz", "tempemail.co.za", "tempemail.com", "tempemail.net",
    "tempinbox.co.uk", "tempinbox.com",
    "tempmail.eu", "tempmail.it", "tempmail.us",
    "tempmail2.com",
    "tempmaildemo.com",
    "tempmailer.com", "tempmailer.de",
    "tempomail.fr",
    "temporarioemail.com.br",
    "temporaryemail.net", "temporaryemail.us",
    "temporaryforwarding.com",
    "temporaryinbox.com",
    "temporarymailaddress.com",
    "tempthe.net",
    "thankdog.net",
    "thc.st",
    "thetempmail.com",
    "thisisnotmyrealemail.com",
    "throwam.com",
    "throwawayemailaddress.com",
    "tittbit.in",
    "tmail.ws",
    "tmailinator.com",
    "toiea.com",
    "toomail.biz",
    "topranklist.de",
    "tradermail.info",
    "trash2009.com", "trash2010.com", "trash2011.com",
    "trash-amil.com",
    "trashbox.eu",
    "trashdevil.com", "trashdevil.de",
    "trashemail.de",
    "trashymail.com", "trashymail.net",
    "turual.com",
    "twinmail.de",
    "tyldd.com",
    "uggsrock.com",
    "upliftnow.com",
    "uplipht.com",
    "venompen.com",
    "veryreallyfakeaddress.com",
    "vidchart.com",
    "viditag.com",
    "viewcastmedia.com", "viewcastmedia.net", "viewcastmedia.org",
    "vomoto.com",
    "vpn.st",
    "vsimcard.com",
    "vubby.com",
    "walala.org",
    "walkmail.net",
    "webemail.me",
    "webm4il.info",
    "wegwerfadresse.de",
    "wegwerfmail.de", "wegwerfmail.info", "wegwerfmail.net", "wegwerfmail.org",
    "wetrainbayarea.com", "wetrainbayarea.org",
    "wh4f.org",
    "whatiaas.com", "whatpaas.com",
    "whyspam.me",
    "wickmail.net",
    "wilemail.com",
    "willhackforfood.biz",
    "willselfdestruct.com",
    "winemaven.info",
    "wronghead.com",
    "wuzup.net", "wuzupmail.net",
    "wwwnew.eu",
    "xagloo.com",
    "xemaps.com",
    "xents.com",
    "xjoi.com",
    "xmaily.com",
    "xoxy.net",
    "yep.it",
    "yogamaven.com",
    "yomail.info",
    "yopmail.com", "yopmail.fr", "yopmail.gq", "yopmail.net",
    "ypmail.webarnak.fr.eu.org",
    "yuurok.com",
    "za.com",
    "zehnminuten.de", "zehnminutenmail.de",
    "zetmail.com",
    "zippymail.info",
    "zoaxe.com",
    "zoemail.com", "zoemail.net", "zoemail.org",
    "zomg.info",
    "zxcv.com", "zxcvbnm.com",
    "zzrgg.com",
    # Новые популярные сервисы (2024-2026)
    "emailfake.com", "email-fake.com",
    "generator.email",
    "1secmail.com", "1secmail.net", "1secmail.org",
    "internxt.com",
    "luxusmail.org",
    "emailable.rocks",
    "emailnax.com",
    "burnermail.io",
    "mailgw.com",
    "tempmailo.com",
    "emaildrop.io",
    "inboxkitten.com",
    "mailpoof.com",
    "33mail.com",
    "anonaddy.com", "anonaddy.me",
    "simplelogin.io", "simplelogin.co",
    # duck.com, relay.firefox.com, privaterelay.appleid.com — НЕ одноразовые,
    # это приватные relay-сервисы реальных людей (DuckDuckGo, Firefox, Apple).
    # Ниже стоит защита, чтобы внешний список не вернул их обратно.
    "icloud.com.disposable",
}


# Домены, которые НИКАКОЙ внешний список не может объявить одноразовыми.
#
# Это пересылки, а не временные ящики: письмо через них доходит до настоящего
# человека в его настоящий почтовый ящик. Пометить такой адрес одноразовым —
# это ложный приговор живому контакту, тот самый, который владелец удалит и
# никогда не узнает, что ошибся не он.
#
# Защита понадобилась не теоретически. Встроенный список исключал их
# сознательно — прямо над этой строкой стоит комментарий об этом, — а
# автообновляемый data/disposable_more.txt возвращал duck.com обратно, и
# решение молча отменялось скачанным файлом.
NEVER_DISPOSABLE = frozenset({
    "duck.com",                     # DuckDuckGo Email Protection
    "relay.firefox.com",            # Firefox Relay
    "privaterelay.appleid.com",     # Apple «Скрыть мою почту»
})


def is_disposable(email: str) -> bool:
    """
    Проверяет, является ли email одноразовым/временным.
    Возвращает True если домен в списке disposable-провайдеров.
    """
    if not isinstance(email, str) or "@" not in email:
        return False
    domain = email.rsplit("@", 1)[1].lower().strip()

    # Пересылка — не одноразовый ящик. Проверяется ПЕРВОЙ: иначе достаточно
    # одной строки в скачанном списке, чтобы живой контакт получил приговор.
    if domain in NEVER_DISPOSABLE:
        return False

    if domain in DISPOSABLE_DOMAINS:
        return True

    parts = domain.split('.')
    for i in range(len(parts) - 1):
        parent = '.'.join(parts[i+1:])
        if parent in DISPOSABLE_DOMAINS and _годится_в_родители(parent):
            return True

    return False


# Слова, которыми называются ЗОНЫ, а не почтовые сервисы. Домен вида
# `<такое слово>.<зона>` — это публичный суффикс: под ним регистрируются
# посторонние люди, и он не принадлежит никому одному.
_СЛОВА_ЗОН = frozenset({
    "co", "com", "net", "org", "edu", "gov", "mil", "int", "biz", "info",
    "ac", "or", "ne", "go", "id", "in", "web", "nom", "pp", "priv", "name",
})

# Короче этого первая метка бывает у зон (`co.uk`, `id.pl`, `msk.ru`,
# `spb.ru`), а не у названий сервисов. Замерено на файлах владельца:
# разделение полное — под запрет попали `co.cc`, `msk.ru`, `id.pl`,
# `edu.net`, `edu.auction`, а `gaggle.net`, `mail-tester.com`, `33mail.com`,
# `mooo.com`, `onlatedotcom.info` и `dmcelements.org` остались рабочими.
_МИН_ДЛИНА_ИМЕНИ_СЕРВИСА = 4


def _годится_в_родители(parent: str) -> bool:
    """Можно ли хоронить ПОДДОМЕНЫ этой записи, а не только её саму.

    ЗАЧЕМ ЭТО НУЖНО. Разбор родителей существует ради поддоменов настоящих
    сервисов: `foo.mailinator.com` ловится только потому, что в базе есть
    `mailinator.com`. Но база пополняется из скачанных списков
    (`extend_disposable_domains`), а там попадаются ЗОНЫ — `co.cc`, `id.pl`,
    `msk.ru`. Зона в списке одноразовых стоит по делу: под `co.cc` когда-то
    раздавали бесплатные имена. Беда в том, что разбор родителей превращал
    одну такую строку в приговор ВСЕМУ, что под ней зарегистрировано.

    Замерено на файлах владельца (789 345 адресов): `echo.msk.ru` — домен
    работающей организации — объявлялся одноразовым и получал скор 0 и
    уверенность 95 без единого запроса к серверу.

    Точное совпадение при этом остаётся в силе: `a@co.cc` по-прежнему
    одноразовый, и никакой другой проверке это правило не мешает.

    ЧЕСТНАЯ ГРАНИЦА. Это признак, а не полный список: `info.pl` и подобные
    зоны с длинным первым словом правило пропустит. Настоящее решение —
    список публичных суффиксов Mozilla; он назван в долге отчёта.
    """
    # Мусор на входе — это «в родители не годится», а не падение: зовут
    # отсюда из рабочих потоков, где исключение стоит потерянного адреса.
    # Поймано фаззингом набора (test_robustness).
    if not isinstance(parent, str) or not parent:
        return False

    # ТОЧНЫЙ ОТВЕТ, КОГДА ОН ЕСТЬ. Список publicsuffix.org и есть ответ на
    # вопрос «под этим именем регистрируются посторонние»: `msk.ru`, `co.uk`,
    # `ddns.net`, `hopto.org` — да; `mailinator.com`, `gaggle.net` — нет, у
    # них один владелец. Признак ниже до этого угадывал по длине первого
    # слова и угадывал не всё: зоны с длинным первым словом (`info.pl`) он
    # пропускал, и одна строка в скачанном списке хоронила всю зону.
    try:
        from core.public_suffix import правил_прочитано, публичный_суффикс
        if правил_прочитано():
            return not публичный_суффикс(parent)
    except Exception:
        pass

    # ПАРАШЮТ. Списка нет (чужая сборка, битая распаковка) — работаем по
    # прежнему признаку, а не отключаем защиту целиком.
    первая = parent.split(".", 1)[0]
    if первая in _СЛОВА_ЗОН:
        return False
    return len(первая) >= _МИН_ДЛИНА_ИМЕНИ_СЕРВИСА


def extend_disposable_domains(domains) -> int:
    """Добавляет домены из авто-обновляемых списков к встроенной базе.

    Встроенный набор захардкожен и не обновляется никогда. SpamFilter грузит
    свежие списки из data/*.txt, но умеет только точное совпадение домена.
    Слив их сюда, мы получаем и свежесть, и проверку ПОДДОМЕНОВ:
    foo.mailinator.com ловится, только если mailinator.com есть в этой базе.

    Возвращает, сколько доменов реально добавилось.
    """
    if (not domains or isinstance(domains, (str, bytes, int, float))
            or not hasattr(domains, "__iter__")):
        return 0
    before = len(DISPOSABLE_DOMAINS)
    for d in domains:
        d = (d or "").strip().lower()
        if d and "." in d and d not in NEVER_DISPOSABLE:
            DISPOSABLE_DOMAINS.add(d)
    return len(DISPOSABLE_DOMAINS) - before


def get_disposable_count() -> int:
    """Возвращает количество доменов в базе."""
    return len(DISPOSABLE_DOMAINS)
