import zlib

RESERVED_TLDS = frozenset({
    "test", "example", "invalid", "localhost",
    "local", "internal", "alt", "onion",
    "localdomain", "lan", "home", "corp", "mail",
    "intranet", "private", "domain", "workgroup",
})

RESERVED_SUFFIXES = ("home.arpa", "in-addr.arpa", "ip6.arpa")


def reserved_zone(domain):
    if not isinstance(domain, str):
        return ""
    низ = domain.strip().lower().rstrip(".")
    if not низ:
        return ""
    for суффикс in RESERVED_SUFFIXES:
        if низ == суффикс or низ.endswith("." + суффикс):
            return суффикс
    зона = низ.rsplit(".", 1)[-1]
    return зона if зона in RESERVED_TLDS else ""


YAHOO_DOMAINS = {
    "yahoo.com", "yahoo.co.uk", "yahoo.co.in", "yahoo.fr", "yahoo.de",
    "yahoo.es", "yahoo.it", "yahoo.com.br", "yahoo.com.ar", "yahoo.com.mx",
    "yahoo.com.au", "yahoo.com.sg", "yahoo.com.hk", "yahoo.com.ph",
    "yahoo.gr", "yahoo.ro", "yahoo.hu", "yahoo.se", "yahoo.no", "yahoo.dk",
    "ymail.com", "rocketmail.com",
    "yahoo.ca", "yahoo.co.jp", "yahoo.in",
}

AOL_DOMAINS = {"aol.com", "aim.com", "verizon.net", "games.com", "love.com"}

NEEDS_CLEAN_IP_DOMAINS = {
    "outlook.com", "hotmail.com", "live.com", "msn.com", "hotmail.co.uk",
    "hotmail.fr", "hotmail.de", "hotmail.es", "hotmail.it", "live.co.uk",
    "live.fr", "passport.com",
    "icloud.com", "me.com", "mac.com",
    "gmx.com", "gmx.de", "gmx.net", "gmx.at",
    "privaterelay.appleid.com",
    "qq.com", "foxmail.com", "163.com", "126.com", "yeah.net", "naver.com",
}

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

LEGIT_HELO_NAMES = [
    "mail.outbound-01.net",
    "smtp.delivery-gateway.com",
    "mta01.mailforward.net",
    "relay.outbound-smtp.org",
    "smtp-out.mailhost.net",
    "mx01.emailgateway.net",
]

DNSBL_ZONES = [
    'b.barracudacentral.org',
    'bl.spamcop.net',
    'psbl.surriel.com',
    'truncate.gbudb.net',
    'all.s5h.net',
    'bl.mailspike.net',
    'dnsbl.dronebl.org',
]

DNSBL_ZONES_IPV6: tuple = ()

SPAMHAUS_ZONE = 'zen.spamhaus.org'

SPAMHAUS_SANITY_LISTED = '2.0.0.127'
SPAMHAUS_SANITY_CLEAN = '1.0.0.127'

PROXY_MAX_CONSECUTIVE_FAILS = 3

MAIL_FROM_POOL = [
    "check@mail.com",
    "verify@email.com",
    "noreply@usa.com",
    "check@gmx.com",
    "verify@post.com",
    "noreply@writeme.com",
]


MAIL_FROM_SPF_MODE = {
    "mail.com": "~all",
    "email.com": "~all",
    "usa.com": "~all",
    "gmx.com": "~all",
    "post.com": "~all",
    "writeme.com": "~all",
}


def mail_from_for(domain):
    if not isinstance(domain, str) or not domain:
        return MAIL_FROM_POOL[0]
    index = zlib.crc32(domain.strip().lower().encode("utf-8", "ignore"))
    return MAIL_FROM_POOL[index % len(MAIL_FROM_POOL)]


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
    if isinstance(mx_record, str) and mx_record and mx_record != "N/A":
        low = mx_record.lower()
        for hints, selectors in _DKIM_BY_MX:
            if any(hint in low for hint in hints):
                return selectors + ['default', 'dkim']
    return _DKIM_FALLBACK


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
