# -*- coding: utf-8 -*-
import time

from core.mail_constants import (AOL_DOMAINS, NEEDS_CLEAN_IP_DOMAINS,
                                 YAHOO_DOMAINS)

__all__ = ["SecondOpinionMixin"]


class SecondOpinionMixin:

    def _confirm_invalid_on_other_mx(self, email, decided_on, mx_records,
                                     needs_ptr, needs_clean, want_country,
                                     deadline, first_proxy=None, почему=None):
        def нечем(причина):
            if почему is not None:
                почему["текст"] = причина
            return None

        if time.monotonic() > deadline:
            return нечем("не успели: истёк общий срок проверки этого адреса")

        domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
        proxy, _все_пойманы = self._pick_for_domain(
            domain, needs_ptr, needs_clean, want_country, avoid_exit_of=first_proxy)
        if first_proxy and proxy is None:
            return нечем("в пуле не осталось прокси с другим выходным IP")

        others = [mx for mx in (mx_records or []) if mx != decided_on]
        target = others[0] if others else decided_on
        if not others and not first_proxy:
            return нечем("у домена один почтовый сервер, а проверка шла "
                         "без прокси — второго выхода тоже нет")

        second = self._do_single_ping(email, target, proxy=proxy)
        status = second.get("status")
        if status == "valid" and proxy and self._lies_about_fake(domain, target, proxy):
            # «Принял» сказал выход, который принимает и выдуманный адрес: его
            self._note_exit_lies(domain, proxy)
            proxy, _все_пойманы = self._pick_for_domain(
                domain, needs_ptr, needs_clean, want_country, avoid_exit_of=first_proxy)
            if proxy is None:
                return нечем("второй выход принимает любые адреса, третьего в пуле нет")
            second = self._do_single_ping(email, target, proxy=proxy)
            status = second.get("status")
        if status == "invalid":
            return True
        if status == "valid":
            return False
        return нечем("второй сервер (%s) ответил неопределённо: %s"
                     % (target, str(second.get("reason") or status)[:80]))
    def confirm_valid_from_other_exit(self, email, mx_records,
                                      first_proxy=None, deadline=None):
        if deadline is not None and time.monotonic() > deadline:
            return None
        domain = email.split("@")[1].lower() if "@" in email else ""
        needs_ptr = domain in YAHOO_DOMAINS or domain in AOL_DOMAINS
        needs_clean = domain in NEEDS_CLEAN_IP_DOMAINS

        proxy, _все_пойманы = self._pick_for_domain(
            domain, needs_ptr, needs_clean, "", avoid_exit_of=first_proxy)
        if first_proxy and proxy is None:
            return None
        if not first_proxy and not self.proxies:
            return None

        target = (mx_records or [None])[0]
        if not target:
            return None
        second = self._do_single_ping(email, target, proxy=proxy)
        status = second.get("status")
        self.__dict__.setdefault("_second_answers", {})[str(email).strip().lower()] = dict(
            second, proxy=proxy)
        if status == "valid":
            return True
        if status in ("invalid", "catchall"):
            return False
        return None

    def second_answer_for(self, email):
        return self.__dict__.get("_second_answers", {}).pop(str(email).strip().lower(), {})

    def _pick_third(self, domain, need_ptr, need_clean, first_proxy, second_proxy):
        пойманы = self.caught_exits_on(domain)
        второй = self._exit_key_of(second_proxy) if second_proxy else None
        не_брать = {p for p in list(self.proxies)
                    if self._exit_key_of(p) in пойманы or self._exit_key_of(p) == второй}
        return self._pick_best_proxy(need_ptr=need_ptr, need_clean=need_clean,
                                     avoid_exit_of=first_proxy, exclude=не_брать)
