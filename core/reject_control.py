# -*- coding: utf-8 -*-
import re

from core.smtp_codes import WEAK_REJECT_REASON, classify_smtp_response

__all__ = ["RejectControlMixin", "compare_rejections", "reject_shape"]

_ADDRESS_RE = re.compile(r"<[^<>\s]*@[^<>\s]*>|[^\s<>@'\"()\[\]]+@[^\s<>@'\"()\[\]]+")
_DIGITS_RE = re.compile(r"\d+")
_ENHANCED_RE = re.compile(r"(?:^|[\s\-])([245]\.\d{1,3}\.\d{1,3})(?![\d.])")


def _as_text(message):
    if isinstance(message, bytes):
        return message.decode("utf-8", "ignore")
    return str(message or "")


def reject_shape(code, message):
    text = _as_text(message)
    enhanced = _ENHANCED_RE.search(text)
    masked = _DIGITS_RE.sub("#", _ADDRESS_RE.sub(" ", text.lower()))
    return code, enhanced.group(1) if enhanced else "", " ".join(masked.split())


def compare_rejections(code, message, fake_code, fake_message):
    if not isinstance(fake_code, int):
        return "inconclusive", {}
    if 200 <= fake_code < 300:
        return "fake_accepted", {"status": "valid", "reason": "%d принят" % fake_code}
    verdict = classify_smtp_response(fake_code, fake_message)
    if reject_shape(code, message) == reject_shape(fake_code, fake_message):
        return "same", verdict
    if (verdict.get("status") == "invalid"
            and WEAK_REJECT_REASON not in str(verdict.get("reason", ""))):
        return "fake_differs", verdict
    return "inconclusive", verdict


class RejectControlMixin:

    def _compare_with_fake_reject(self, server, domain, result, code, message, email):
        if (not domain or result.get("status") != "invalid" or result.get("via_vrfy")
                or WEAK_REJECT_REASON not in str(result.get("reason", ""))):
            return
        fake = self._control_address(domain)
        if str(fake).strip().lower() == str(email or "").strip().lower():
            return
        try:
            fake_code, fake_message = server.rcpt(fake)
            fake_code = int(fake_code)
        except Exception:
            fake_code, fake_message = None, b""
        итог, ответ = compare_rejections(code, message, fake_code, fake_message)
        result["fake_reject_compare"] = итог
        if итог == "same":
            result["reason"] = "%s [выдуманный адрес получил тот же отказ]" % result.get("reason", "")
        elif итог == "fake_accepted":
            result["status"] = "risky"
            result["reason"] = ("%s Сервер отверг этот адрес, а выдуманный принял — отказ "
                                "именно этому получателю (политика), а не «ящика нет» "
                                "(не доказано)" % code)
        elif итог == "fake_differs":
            result["status"] = "risky"
            result["reason"] = ("%s Несуществующему адресу сервер отвечает иначе («%s»), "
                                "а этот получил другой отказ — отказали не потому, что "
                                "ящика нет (не доказано)"
                                % (code, str(ответ.get("reason", ""))[:60]))
