# -*- coding: utf-8 -*-
from concurrent.futures import ThreadPoolExecutor

from core.canary import canary_address
from core.confirmation import rejects_fake

__all__ = ["VerdictRevisionMixin"]


class VerdictRevisionMixin:
    def _second_opinion_on_valid(self, email, res):
        if self.network is None:
            return None
        mx = res.get("mx_records") or ([res["mx_record"]]
                                       if res.get("mx_record") else [])
        if not mx:
            return None
        try:
            итог = self.network.confirm_valid_from_other_exit(
                email, list(mx), first_proxy=res.get("proxy"))
        except Exception:
            return None
        взять = getattr(self.network, "second_answer_for", None)
        if callable(взять):
            try:
                res["second_opinion_answer"] = взять(email)
            except Exception:
                pass
        return итог
    def _fly_canary(self, email, res):
        watch = getattr(self, "canary", None)
        if watch is None or self.network is None:
            return False
        try:
            domain = email.rsplit("@", 1)[1].lower()
        except Exception:
            return False
        proxy = res.get("proxy")
        exit_ip = self._exit_key(proxy)[0]
        mx = res.get("mx_records") or ([res["mx_record"]]
                                       if res.get("mx_record") else [])
        if mx:
            self.__dict__.setdefault("_canary_routes", {})[(exit_ip, domain)] = (proxy, list(mx))
        номер = watch.note_valid(exit_ip, domain)
        self.__dict__.setdefault("_valid_numbers", {})[str(email).strip().lower()] = номер
        if not mx:
            return False
        covers = watch.claim_probe(exit_ip, domain)
        if covers is None:
            return False
        return self._probe_pair(exit_ip, domain, proxy, mx, covers)

    def _probe_pair(self, exit_ip, domain, proxy, mx, covers=None):
        watch = self.canary
        одна_сессия = getattr(self.network, "_do_single_ping", None)
        try:
            if callable(одна_сессия):
                # ОДНА сессия через ровно этот прокси: без перебора выходов и
                ответ = одна_сессия(canary_address(domain), list(mx)[0], proxy=proxy)
                ответ = dict(ответ or {}, proxy=proxy)
            else:
                ответ = self.network.stealth_smtp_ping(
                    canary_address(domain), list(mx), prefer_exit_of=proxy)
            статус = ответ.get("status")
        except Exception:
            # иначе пара больше не получила бы ни одной пробы за прогон.
            watch.release(exit_ip, domain, covers)
            return False
        if self._exit_key(ответ.get("proxy"))[0] != exit_ip:
            watch.release(exit_ip, domain, covers)
            return False
        if статус in ("invalid", "risky", "disabled") and not rejects_fake(ответ):
            # Отказ по форме, но не по сути: «550 … try again later», предел
            статус = "unknown"
        if not watch.record(exit_ip, domain, статус, covers=covers):
            return False
        отметить = getattr(self.network, "mark_exit_caught", None)
        if callable(отметить):
            отметить(exit_ip, domain)

        self.callbacks['on_log'](
            "[DEAD] Канарейка вернулась живой: %s принял заведомо "
            "несуществующий адрес с выхода %s. Все «Годен» по этому домену с "
            "этого выхода НЕДОКАЗУЕМЫ — виноват прокси, не база."
            % (domain, exit_ip or "прямого соединения"), "dead")
        return True

    def _final_canaries(self, trapped):
        watch = getattr(self, "canary", None)
        if watch is None or self.network is None or self.network.aborted():
            return 0
        домены = set(trapped or []) | set(watch.compromised_domains())
        пущено = self._cover_tails(домены | self._giant_route_domains())
        домены |= set(watch.compromised_domains())
        self._recheck_revoked(домены)
        return пущено

    def _giant_route_domains(self):
        гиганты = set()
        for (_выход, домен) in list(self.__dict__.get("_canary_routes", {})):
            try:
                if self.network._is_never_catchall(домен):
                    гиганты.add(домен)
            except Exception:
                continue
        return гиганты

    def _cover_tails(self, домены):
        watch = self.canary
        пущено = 0
        for (exit_ip, domain), (proxy, mx) in list(self.__dict__.get("_canary_routes", {}).items()):
            if domain not in домены or self.network.aborted():
                continue
            if watch.valid_count(exit_ip, domain) <= watch.honest_upto(exit_ip, domain):
                continue
            if watch.is_compromised(exit_ip, domain):
                continue
            covers = watch.claim_now(exit_ip, domain)
            self._probe_pair(exit_ip, domain, proxy, mx, covers)
            if (watch.honest_upto(exit_ip, domain) < covers
                    and not watch.is_compromised(exit_ip, domain)
                    and not self.network.aborted()):
                covers = watch.claim_now(exit_ip, domain)
                self._probe_pair(exit_ip, domain, proxy, mx, covers)
            пущено += 1
        if пущено:
            self.callbacks['on_log'](
                "[INFO] Завершающих канареек: %d — по выходам, у которых были «Годен» "
                "после последней пробы." % пущено, "info")
        return пущено

    def _recheck_revoked(self, домены):
        net = self.network
        проверить = getattr(net, "check_email", None)
        if not callable(проверить) or net.aborted():
            return 0, 0
        try:
            лжецы = set(net.tarpit_pairs()) | self.canary.lying_pairs()
        except Exception:
            return 0, 0
        уцелеют = self._spared_valid(домены, лжецы)
        исходные = dict(self.__dict__.get("_valid_original", {}))
        кандидаты = sorted(адрес for адрес in list(self.__dict__.get("_valid_exits", {}))
                           if адрес.rsplit("@", 1)[-1] in домены and адрес not in уцелеют)
        if not кандидаты:
            return 0, 0
        опора = {}
        for (выход, домен), (прокси, _mx) in list(self.__dict__.get("_canary_routes", {}).items()):
            if домен not in домены or (выход, домен) in лжецы or not self._exit_key(прокси)[1]:
                continue
            честен_до = self.canary.honest_upto(выход, домен)
            if честен_до >= 0 and честен_до > опора.get(домен, (-1, None))[0]:
                опора[домен] = (честен_до, прокси)
        подтверждено = []

        def переспросить(адрес):
            if net.aborted():
                return
            email = исходные.get(адрес, адрес)
            try:
                res = проверить(email, prefer_exit_of=опора.get(
                    адрес.rsplit("@", 1)[-1], (-1, None))[1])
            except Exception:
                return
            if res.get("status") != "valid" or res.get("aborted"):
                return
            if not self._exit_key(res.get("proxy"))[1]:
                return
            if (getattr(self, "confirm_valid", False)
                    and self._second_opinion_on_valid(email, res) is False):
                return
            self._fly_canary(email, res)
            self._note_valid_exit(email, res)
            подтверждено.append(адрес)

        with ThreadPoolExecutor(max_workers=min(8, len(кандидаты))) as пул:
            list(пул.map(переспросить, кандидаты))
        if подтверждено:
            self._cover_tails(домены)
        self.callbacks['on_log'](
            "[INFO] Переспрошено честным выходом «Годен», которые иначе ушли бы в "
            "«Неизвестно»: %d; снова «Годен» — %d (сохранятся, если их выход прошёл "
            "канарейку)." % (len(кандидаты), len(подтверждено)), "info")
        return len(кандидаты), len(подтверждено)
    def _recheck_if_first_exit_lies(self, email, res, ctx=None, dom_key=""):
        net = self.network
        if res.get("retried_without_liar") or net is None:
            return None
        проверить = getattr(net, "check_email", None)
        лжёт = getattr(net, "_lies_about_fake", None)
        mx = res.get("mx_records") or ([res["mx_record"]] if res.get("mx_record") else [])
        if not callable(проверить) or not callable(лжёт) or not mx or "@" not in email:
            return None
        domain = email.rsplit("@", 1)[1].lower()
        try:
            if not лжёт(domain, mx[0], res.get("proxy")):
                return None
            net._note_exit_lies(domain, res.get("proxy"))
            свежий = dict(проверить(email), retried_without_liar=True)
        except Exception:
            return None
        if свежий.get("aborted"):
            return None
        self._uncount_first_answer(ctx, dom_key)
        self.callbacks['on_log'](
            "[INFO] Выход, принявший адрес вопреки второму, принимает и выдуманный — "
            "пойман; адрес переспрошен другим выходом: %s" % свежий.get("status"), "info")
        return свежий

    @staticmethod
    def _uncount_first_answer(ctx, dom_key):
        if ctx is None or not dom_key:
            return
        with ctx.lock:
            st = ctx.domain_stats.get(dom_key)
            if st:
                st["total"] = max(0, st["total"] - 1)
                st["valid"] = max(0, st["valid"] - 1)

    def _third_opinion(self, email, res, ctx=None, dom_key=""):
        from core.mail_constants import AOL_DOMAINS, NEEDS_CLEAN_IP_DOMAINS, YAHOO_DOMAINS
        from core.smtp_codes import WEAK_REJECT_REASON
        net = self.network
        if net is None or "@" not in email:
            return None
        второй = res.get("second_opinion_answer") or {}

        def явное_нет(ответ):
            return (ответ.get("status") == "invalid"
                    and WEAK_REJECT_REASON not in str(ответ.get("reason", "")))

        mx = res.get("mx_records") or ([res["mx_record"]] if res.get("mx_record") else [])
        первый = res.get("proxy")
        if not mx or not первый or not второй.get("proxy") or not явное_нет(второй):
            return None
        domain = email.rsplit("@", 1)[1].lower()
        try:
            третий = net._pick_third(domain, domain in YAHOO_DOMAINS or domain in AOL_DOMAINS,
                                     domain in NEEDS_CLEAN_IP_DOMAINS, первый, второй["proxy"])
            if третий is None:
                return None
            ответ = net._do_single_ping(email, list(mx)[0], proxy=третий)
            if not явное_нет(ответ):
                return None
            if not net._is_never_catchall(domain) and net.postmaster_is_honored(
                    domain, list(mx)[0]) is False:
                return None
            net._note_exit_lies(domain, первый)
        except Exception:
            return None
        self._uncount_first_answer(ctx, dom_key)
        self.callbacks['on_log'](
            "[INFO] Спор выходов решён третьим: второй и третий получили явное «нет такого "
            "ящика», первый, принявший адрес, помечен на домене %s." % domain, "info")
        return {"status": "invalid",
                "reason": ("%s [второй и третий выходы получили явный отказ; первый, "
                           "принявший адрес, помечен на домене]" % ответ.get("reason", "")),
                "mx_record": list(mx)[0], "mx_records": list(mx), "proxy": третий,
                "third_opinion": "invalid"}

    def _split_catchall_from_tarpit(self, proven, trapped):
        net = getattr(self, "network", None)
        гиганты = []
        for d in proven or []:
            try:
                if net is not None and net._is_never_catchall(d):
                    гиганты.append(d)
            except Exception:
                pass
        if not гиганты:
            return list(proven or []), list(trapped or [])
        return ([d for d in proven if d not in гиганты],
                sorted(set(trapped or []) | set(гиганты)))
    def _catchall_disproven(self, domain):
        net = getattr(self, "network", None)
        if net is None:
            return False
        try:
            if net._is_never_catchall(domain):
                return True
            if domain in net.behind_gateway_domains():
                return True
            with net.catchall_lock:
                return net.catchall_cache.get(domain) is False
        except Exception:
            return False

    def _behind_gateway_spared(self):
        try:
            return self.network.behind_gateway_valid() if self.network is not None else set()
        except Exception:
            return set()
    def _forget_cached(self, domains, why):
        cache = getattr(self, "cache", None)
        if cache is None or not domains:
            return 0
        forgotten = 0
        for domain in domains:
            try:
                forgotten += cache.forget_domain(domain)
            except Exception:
                pass
        if forgotten:
            self.callbacks['on_log'](
                "[INFO] Из кэша убрано вердиктов: %d (%s). Следующий запуск "
                "проверит эти адреса заново, а не достанет старый «Годен»."
                % (forgotten, why), "info")
        return forgotten
    def _exit_key(self, proxy):
        if not proxy:
            return "прямое соединение", True
        try:
            ip = self.network.exit_ip_of(proxy) if self.network is not None else ""
        except Exception:
            ip = ""
        return (str(ip).lower(), True) if ip else (str(proxy).lower(), False)

    def _note_valid_exit(self, email, res):
        выходы = self.__dict__.setdefault("_valid_exits", {})
        key, known = self._exit_key(res.get("proxy"))
        адрес = str(email).strip().lower()
        watch = getattr(self, "canary", None)
        номер = self.__dict__.get("_valid_numbers", {}).pop(адрес, None)
        try:
            if номер is None:
                номер = watch.valid_count(key, адрес.rsplit("@", 1)[-1]) if watch else 0
        except Exception:
            номер = 0
        выходы[адрес] = (key, known, номер)
        self.__dict__.setdefault("_valid_original", {})[адрес] = str(email).strip()

    def _spared_valid(self, domains, liars):
        watch = getattr(self, "canary", None)
        if watch is None or not hasattr(watch, "honest_upto"):
            return set()
        wanted = {str(d).strip().lower().lstrip("@") for d in domains or []}
        spare = set()
        for email, (key, known, номер) in list(self.__dict__.get("_valid_exits", {}).items()):
            domain = email.rsplit("@", 1)[-1]
            if (domain in wanted and known and (key, domain) not in liars
                    and watch.vouched(key, domain)
                    and watch.honest_upto(key, domain) >= номер):
                spare.add(email)
        return spare

    def _log_spared(self, spared, why):
        if spared:
            self.callbacks['on_log'](
                "[INFO] Отзыв по выходу (%s): сохранено «Годен» — %d; их выход на "
                "этом домене проверен канарейкой и честно отверг выдуманный адрес."
                % (why, len(spared)), "info")

    def _revise(self, domains, new_status, note, spare=None):
        handler = self.callbacks.get('on_revise')
        if handler is None or not domains:
            return 0
        status = None if new_status is None else str(new_status)
        try:
            if spare:
                try:
                    return int(handler(list(domains), status, str(note), set(spare)) or 0)
                except TypeError:
                    pass
            return int(handler(list(domains), status, str(note)) or 0)
        except Exception:
            return 0
