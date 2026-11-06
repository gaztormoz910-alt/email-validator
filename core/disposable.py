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
    "mailgw.com",
    "tempmailo.com",
    "emaildrop.io",
    "inboxkitten.com",
    "mailpoof.com",
    # Пересылок здесь нет НАМЕРЕННО — ни DuckDuckGo, Firefox и Apple, ни
    # SimpleLogin, addy.io, Proton Pass, 33mail, Burner Mail. Их полный перечень
    # и причина — в NEVER_DISPOSABLE ниже. Раньше часть из них (anonaddy.*,
    # simplelogin.*, 33mail.com, burnermail.io) стояла в этом списке, и живой
    # контакт получал «Trap/Disposable» без единого вопроса серверу.
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
#
# ЭТО ЕДИНСТВЕННЫЙ ПЕРЕЧЕНЬ ПЕРЕСЫЛОК В ПРОГРАММЕ. core/heuristics.py берёт
# его отсюда же (PRIVACY_RELAY_DOMAINS): там был свой перечень из 14 доменов с
# пометкой «core/disposable.py специально не считает их одноразовыми», а здесь
# стояли три. Восемь из тех четырнадцати этот модуль хоронил (аудит 03.11.2026,
# .unlazy/rivals/ОТЧЁТ.md, E1) — два списка одного знания разошлись молча.
#
# Граница — по тому, живёт ли адрес. Пересылка живёт, пока её не отключил
# хозяин, и всё это время письма доходят до него. spamgourmet.com сюда не
# входит: его адреса сами умирают после заданного числа писем, то есть созданы,
# чтобы их бросить, — это одноразовый ящик по определению программы.
NEVER_DISPOSABLE = frozenset({
    "duck.com",                     # DuckDuckGo Email Protection
    "relay.firefox.com",            # Firefox Relay (старые адреса)
    "mozmail.com",                  # Firefox Relay
    "privaterelay.appleid.com",     # Apple «Скрыть мою почту»
    "icloud.com",                   # Apple «Скрыть мою почту» (новые адреса)
    "simplelogin.com", "simplelogin.io", "simplelogin.co",
    "simplelogin.fr", "aleeas.com", "slmail.me", "8shield.net",   # SimpleLogin
    # Общие пулы SimpleLogin: MX у всех четырёх — mx1/mx2.simplelogin.co (замер
    # DNS 04.11.2026), сайт ведёт на simplelogin.io. slmails.com стоит в
    # скачиваемом data/disposable_more.txt, и его пользователи получали
    # Trap/Disposable: первый перечень его не знал.
    "dralias.com", "silomails.com", "slmails.com", "8alias.com",
    "anonaddy.com", "anonaddy.me", "addy.io",                     # addy.io
    "passmail.net", "passmail.com", "passinbox.com", "passfwd.com",   # Proton Pass
    "pass2mail.com",                # Proton Pass: сайт ведёт на proton.me/pass, MX — simplelogin.co
    "33mail.com",                   # 33mail
    "burnermail.io",                # Burner Mail
    "erine.email",                  # Erine Email
    # Forward Email: домены для платных клиентов (пост команды сервиса на
    # discuss.privacyguides.net, 02.01.2024); MX — mx1/mx2.forwardemail.net.
    "mailsire.com", "hideaddress.net", "secret.fyi", "hash.fyi",
    # Маски Abine Blur (IronVest): справка IronVest велит внести @opayq.com в
    # безопасные отправители, письмо пересылается «from a MASKED EMAIL you
    # created using Blur». Хоронил его даже курируемый data/disposable.txt.
    "opayq.com",
    # Те же маски Blur: MX blurme.net — smtp7.opayq.com, у blurmail.net — те же
    # серверы, что у opayq.com, у обоих SPF include:opayq.com (замер DNS 06.11.2026).
    "blurme.net", "blurmail.net",
})


# Живые почтовики, которых программа знает по своим таблицам (core/filters.py,
# BLACKLIST_SENTINELS). Достаются лениво и один раз: core.filters при импорте
# собирает стража из таблиц провайдеров, а зовут отсюда на каждый адрес базы.
_ЖИВЫЕ_ПОЧТОВИКИ = None


def _живые_почтовики():
    global _ЖИВЫЕ_ПОЧТОВИКИ
    if _ЖИВЫЕ_ПОЧТОВИКИ is None:
        try:
            from core.filters import BLACKLIST_SENTINELS
            стражи = frozenset(BLACKLIST_SENTINELS)
        except Exception:
            # Без стража проверка работает как раньше, а не падает: зовут
            # отсюда из рабочих потоков, где исключение стоит потерянного адреса.
            стражи = frozenset()
        # Почтовая инфраструктура крупных служб (таблица ниже) — тоже живая
        # почта. forwardemail.net, где живут support@ и abuse@ самого сервиса,
        # и yandex.net хоронил широкий сборник, хотя программа сама числит их
        # «никогда не одноразовыми» (вторая проверка полноты, 06.11.2026).
        _ЖИВЫЕ_ПОЧТОВИКИ = стражи | _MX_NEVER_DISPOSABLE
    return _ЖИВЫЕ_ПОЧТОВИКИ


def _цепочка(domain):
    """Домен и его родители до второго уровня: `a.b.c.com` → a.b.c.com, b.c.com, c.com."""
    # Мусор на входе — пустая цепочка, а не падение: зовут отсюда из рабочих
    # потоков, где исключение стоит потерянного адреса (test_robustness).
    if not isinstance(domain, str) or not domain:
        return []
    метки = domain.split(".")
    return [".".join(метки[i:]) for i in range(len(метки) - 1)]


def is_protected_domain(domain) -> bool:
    """Домен, который одноразовым не бывает ни по какому списку.

    Пересылка — не одноразовый ящик, и её поддомены тоже: у addy.io и 33mail
    ящик пользователя — это `user.anonaddy.com` и `bearcat.33mail.com`. Живой
    почтовик одноразовым не бывает, в каком бы списке он ни оказался:
    скачанные списки страж чистит при загрузке (core/filters.py), а встроенный
    набор выше — нет, и anonaddy.me с simplelogin.io, которых программа сама
    числит живыми, хоронились именно им (аудит, E2). Одно правило на все пути —
    список, базу и шаг по почтовому серверу (core/settle.py).
    """
    if not isinstance(domain, str) or not domain:
        return False
    domain = domain.lower().strip()
    if any(звено in NEVER_DISPOSABLE for звено in _цепочка(domain)):
        return True
    return domain in _живые_почтовики()


def is_disposable(email: str) -> bool:
    """
    Проверяет, является ли email одноразовым/временным.
    Возвращает True если домен в списке disposable-провайдеров.
    """
    if not isinstance(email, str) or "@" not in email:
        return False
    domain = email.rsplit("@", 1)[1].lower().strip()

    # Защищённый домен проверяется ПЕРВЫМ: иначе достаточно одной строки в
    # скачанном списке, чтобы живой контакт получил приговор.
    if is_protected_domain(domain):
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


# Почтовая инфраструктура крупных служб, которую НИКОГДА нельзя считать
# одноразовой, даже если её имя попало в скачанный список.
#
# Одноразовость по почтовому серверу проверяется ниже по его ИМЕНИ: MX домена
# принадлежит известному одноразовому сервису — значит и домен его. Беда была
# бы, если бы в список попал домен, на серверах которого живут тысячи
# настоящих компаний (Google Workspace, Microsoft 365, хостинг GoDaddy,
# Namecheap, Zoho): одна строка в чужом списке похоронила бы их всех без
# единого запроса. Поэтому страж — здесь, отдельно от стража по доменам
# адресов (core/filters.BLACKLIST_SENTINELS), который проверяется тоже.
_MX_NEVER_DISPOSABLE = frozenset({
    "google.com", "googlemail.com", "gmail.com", "outlook.com",
    "hotmail.com", "microsoft.com", "office365.us", "yandex.net",
    "yandex.ru", "mail.ru", "yahoodns.net", "yahoo.com", "icloud.com",
    "apple.com", "zoho.com", "zoho.eu", "zohomail.com", "protonmail.ch",
    "proton.me", "messagingengine.com", "secureserver.net",
    "registrar-servers.com", "amazonaws.com", "amazonses.com",
    "mailgun.org", "sendgrid.net", "ovh.net", "gandi.net", "ionos.com",
    "ionos.de", "1and1.com", "hostinger.com", "titan.email",
    "privateemail.com", "mimecast.com", "pphosted.com", "cloudflare.net",
    "improvmx.com", "forwardemail.net", "pobox.com", "tutanota.de",
    "mailbox.org", "posteo.de", "fastmail.com", "gmx.net", "web.de",
    "rambler.ru", "ukr.net", "qq.com", "163.com", "naver.com",
})


def disposable_mx_owner(mx_hosts) -> str:
    """Одноразовый сервис, которому принадлежит почтовый сервер домена.

    Возвращает имя сервиса (домен из списка одноразовых) или пустую строку.
    Узнаётся по имени MX-хоста и его родителям с той же защитой зон, что и у
    обычной проверки (`_годится_в_родители`): `mx.mailinator.com` принадлежит
    `mailinator.com`, а `mx.foo.co.cc` не принадлежит зоне `co.cc`.
    """
    if isinstance(mx_hosts, str):
        mx_hosts = [mx_hosts]
    if not isinstance(mx_hosts, (list, tuple)):
        return ""
    try:
        from core.filters import BLACKLIST_SENTINELS
    except Exception:
        BLACKLIST_SENTINELS = frozenset()
    for host in mx_hosts:
        if not isinstance(host, str) or not host or host == "N/A":
            continue
        имя = host.strip().lower().rstrip(".")
        метки = имя.split(".")
        цепочка = [".".join(метки[i:]) for i in range(len(метки) - 1)]
        if any(звено in _MX_NEVER_DISPOSABLE or звено in BLACKLIST_SENTINELS
               or звено in NEVER_DISPOSABLE for звено in цепочка):
            continue
        for звено in цепочка:
            if звено in DISPOSABLE_DOMAINS and (звено == имя or _годится_в_родители(звено)):
                return звено
    return ""


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
