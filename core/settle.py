# -*- coding: utf-8 -*-
from core.cleaner import normalize_for_dedup
from core.disposable import disposable_mx_owner, is_protected_domain
from core.heuristics import trap_word_in_local
from core.verdict import verdict_confidence

__all__ = ["SettleMixin", "DISPLAY_OF", "SettleContext"]


DISPLAY_OF = {
    "valid": "Valid",
    "invalid": "Invalid/Bounce",
    "risky": "Risky",
    "unknown": "Unknown",
    "catchall": "Unknown",
    "full": "Mailbox Full",
    "disabled": "Disabled",
    "unconfirmed": "Unconfirmed",
    "trap": "Trap/Disposable",
    "disposable": "Trap/Disposable",
    "greylisted": "Risky",
}


class SettleContext(object):

    __slots__ = ("domain_stats", "lock", "state")

    def __init__(self, domain_stats, lock, state):
        self.domain_stats = domain_stats
        self.lock = lock
        self.state = state


class SettleMixin:


    def _emit_trap(self, email, data, reason, provider_type, basis_status,
                   enable_ai, mx="N/A"):
        data["engagement_score"] = 0
        data["engagement_grade"] = "Dead"
        data["provider_type"] = provider_type
        уверенность, основание = verdict_confidence(basis_status, reason)
        data["verdict_confidence"] = уверенность
        data["verdict_basis"] = основание
        self._enrich_offline(email, data, "Trap/Disposable", enable_ai)
        self._emit(email, "Trap/Disposable", reason, mx, data)

    def _trap_by_name(self, email, data, enable_ai, deep_ping=False):
        слово = trap_word_in_local(email)
        if not слово:
            return False
        if deep_ping:
            data["trap_word"] = слово
            return False
        self._emit_trap(email, data,
                        "Имя ящика похоже на ловушку для рассылок («%s») — "
                        "писать нельзя" % слово,
                        "Ловушка по имени", "trap", enable_ai)
        return True

    def _settle_trap_word(self, email, data, res, enable_ai, ctx):
        self._emit_trap(email, data,
                        "Имя ящика похоже на ловушку для рассылок («%s») — писать "
                        "нельзя; сервер: %s" % (data.get("trap_word"),
                                                 res.get("reason") or res.get("status")),
                        "Ловушка по имени", "trap", enable_ai,
                        mx=res.get("mx_record", "N/A"))
        ctx.state.mark_done(normalize_for_dedup(email))

    def _emit_unresolved(self, email, why, data, enable_ai):
        if data.get("trap_word"):
            self._emit_trap(email, data,
                            "Имя ящика похоже на ловушку для рассылок («%s») — писать "
                            "нельзя; сервер так и не ответил: %s" % (data["trap_word"], why),
                            "Ловушка по имени", "trap", enable_ai)
            return
        self._emit(email, "Unknown", why, "N/A", data)

    def _disposable_by_mx(self, email, data, enable_ai):
        спросить = getattr(self.network, "get_mx_records", None)
        if спросить is None or "@" not in email:
            return False
        if is_protected_domain(email.rsplit("@", 1)[1]):
            return False
        try:
            mx = спросить(email.rsplit("@", 1)[1].strip().lower())
        except Exception:
            return False
        if not mx:
            return False
        хозяин = disposable_mx_owner(mx)
        if not хозяин:
            return False
        data["provider_name"] = "Disposable"
        data["domain_type"] = "Disposable"
        self._emit_trap(email, data,
                        "Почтовый сервер домена принадлежит одноразовому "
                        "сервису (%s) — ящик живёт минуты" % хозяин,
                        "Disposable (по почтовому серверу)", "trap", enable_ai,
                        mx=mx[0] if isinstance(mx, list) and mx else "N/A")
        return True


    def _mark_typo_domain(self, email, data, mx):
        mx = mx or ""
        cleaner = getattr(self, "cleaner", None)
        if cleaner is None or not mx or mx == "N/A" or data.get("typo_of"):
            return
        try:
            похоже = cleaner.suggest_domain_fix(email)
        except Exception:
            return
        if похоже and "@" in похоже:
            data["typo_of"] = похоже.rsplit("@", 1)[1]

    def _typo_hint_on_live_mx(self, email, data, res, fix_typos):
        self._mark_typo_domain(email, data, res.get("mx_record"))
        if res.get("status") not in ("catchall", "unknown", "risky", "unconfirmed"):
            return
        if data.get("suggested_email"):
            return
        self._подсказать_опечатку(email, data, fix_typos)
        подсказка = data.get("suggested_email")
        if подсказка:
            res["reason"] = "%s | Похоже на опечатку: имелся в виду %s?" % (
                res.get("reason", ""), подсказка.rsplit("@", 1)[1])


    def _settle(self, email, data, is_role, res, enable_ai, ctx):
        raw_status = res.get("status", "unknown")
        status_display = DISPLAY_OF.get(raw_status, "Unknown")

        if data.get("trap_word") and raw_status != "invalid":
            return self._settle_trap_word(email, data, res, enable_ai, ctx)

        dom_key = email.rsplit("@", 1)[1].lower() if "@" in email else ""
        if dom_key:
            with ctx.lock:
                st = ctx.domain_stats.setdefault(dom_key, {"total": 0, "valid": 0})
                st["total"] += 1
                if raw_status == "valid":
                    st["valid"] += 1

        if raw_status == "valid" and getattr(self, "confirm_valid", False):
            итог = self._second_opinion_on_valid(email, res)
            if итог is False:
                повтор = self._recheck_if_first_exit_lies(email, res, ctx, dom_key)
                if повтор is None:
                    повтор = self._third_opinion(email, res, ctx, dom_key)
                if повтор is not None:
                    return self._settle(email, data, is_role, повтор, enable_ai, ctx)
                raw_status = "unknown"
                status_display = "Unknown"
                res["status"] = "unknown"
                res["reason"] = ("Второй выход отверг адрес, первый принял — "
                                 "доказательства нет ни у одной стороны")
            elif итог is None:
                res["valid_second_opinion"] = "unavailable"
            else:
                res["valid_second_opinion"] = "agreed"

        if raw_status == "valid":
            self._fly_canary(email, res)
            self._note_valid_exit(email, res)

        if dom_key:
            with ctx.lock:
                st = ctx.domain_stats.get(dom_key) or {}
            всего = int(st.get("total") or 0)
            if всего:
                data["domain_valid_ratio"] = round(int(st.get("valid") or 0) / float(всего), 3)
                data["domain_checked"] = всего

        try:
            data["checked_as"] = (self.network.probe_form(email)
                                  if self.network is not None else email)
        except Exception:
            data["checked_as"] = email

        original_smtp_status = status_display
        data["role_address"] = bool(is_role)
        if is_role and status_display == "Valid":
            status_display = "Role-based"

        self._enrich_and_score(email, data, res, status_display,
                               original_smtp_status, is_role, enable_ai)
        self._emit(email, status_display, res.get("reason", ""),
                   res.get("mx_record", "N/A"), data)
        ctx.state.mark_done(normalize_for_dedup(email))
