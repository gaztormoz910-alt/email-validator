# -*- coding: utf-8 -*-
import os
import threading
from core.cache import ResultCache
from core.filters import SpamFilter
from core.github_parser import BlacklistDownloader
from core.network import NetworkValidator
from core.activity import net_budget
from core.ai_engine import EmailAI
from core.provider import extend_free_domains
from core.paths import data_path
from core.hostport import has_ipv6_route, ipv6_literal

__all__ = ["PipelineSetupMixin"]


def _count_ipv6_proxies(stream, counter):
    from core.proxy_transport import _parse_proxy

    for proxy in stream:
        if isinstance(proxy, str) and ("[" in proxy or proxy.count(":") >= 5
                                       or "::" in proxy):
            parsed = _parse_proxy(proxy)
            if parsed and ipv6_literal(parsed[0]):
                counter[0] += 1
        yield proxy


def _warn_ipv6_unreachable(log, count, route=has_ipv6_route):
    if count <= 0 or route():
        return False
    log("[DEAD] Прокси с IPv6-адресом: %d — и все они недоступны С ЭТОГО "
        "КОМПЬЮТЕРА: у него нет выхода в интернет по IPv6. Сами прокси тут ни "
        "при чём. Нужен IPv6 от провайдера (и включённый в роутере) либо прокси "
        "со входом по IPv4 — выход у них может быть и IPv6." % count, "dead")
    return True


class PipelineSetupMixin:
    def _домен_принимает_почту(self, domain):
        if not domain or getattr(self, "network", None) is None:
            return None
        try:
            записи = self.network.get_mx_records(domain)
        except Exception:
            return None
        if записи is None:
            return None
        return bool(записи)

    def _http_proxies(self):
        try:
            if self.network and self.network.has_proxies_configured():
                from core.network import build_proxy_dict
                proxy = self.network._pick_best_proxy()
                if proxy:
                    return build_proxy_dict(proxy)
        except Exception:
            pass
        return None
    def _start_profile_refresher(self, timeout, workers, interval=600):
        self._refresh_stop = stop = threading.Event()

        def loop():
            while not stop.wait(interval):
                if not self.is_running or not self.network:
                    return
                try:
                    stats = self.network.refresh_proxy_profiles(
                        timeout=timeout, workers=workers)
                except Exception:
                    continue
                if not stats.get("checked"):
                    continue
                if stats["ip_changed"] or stats["ptr_lost"] or stats["ptr_gained"]:
                    self.callbacks['on_log'](
                        f"[PROXY] Профиль обновлён: сменили IP — {stats['ip_changed']}, "
                        f"потеряли PTR — {stats['ptr_lost']}, "
                        f"получили PTR — {stats['ptr_gained']}.", "info")

        self._refresh_thread = threading.Thread(target=loop, daemon=True)
        self._refresh_thread.start()
    def _share_abort_event(self):
        event = getattr(self, "_abort_event", None)
        if event is not None and self.network is not None:
            self.network.abort_event = event

    def _stop_profile_refresher(self):
        stop = getattr(self, "_refresh_stop", None)
        if stop is not None:
            stop.set()
    def _profile_live_proxies(self, live_proxies, timeout, threads):
        proxy_profiles = {}
        if live_proxies:
            try:
                from core.network import profile_proxies
                self.callbacks['on_log'](
                    f"[INFO] Профилирование {len(live_proxies)} прокси "
                    "(выходной IP, PTR, чёрные списки)...", "info")

                def on_prof(done, total, ptr_n, bl_n):
                    self.callbacks['on_log'](
                        f"[PROXY] Профиль... {done}/{total} | с PTR: {ptr_n} | в списках: {bl_n}", "info")

                remembered = self.network.recall_proxy_profiles(live_proxies)
                fresh_needed = [p for p in live_proxies if p not in remembered]
                if remembered:
                    self.callbacks['on_log'](
                        "[PROXY] Из прошлого запуска помню профиль %d прокси "
                        "из %d — заново проверяю только остальных."
                        % (len(remembered), len(live_proxies)), "info")

                proxy_profiles = dict(remembered)
                if fresh_needed:
                    proxy_profiles.update(profile_proxies(
                        fresh_needed, timeout=timeout, workers=threads,
                        progress_callback=on_prof,
                        should_stop=lambda: getattr(self, "_stop_requested", False)))

                if getattr(self, "_stop_requested", False):
                    self.callbacks['on_log'](
                        "[INFO] Профилирование прервано «Стопом»: снято %d из %d."
                        % (len(proxy_profiles), len(live_proxies)), "info")
                    return proxy_profiles

                vals = list(proxy_profiles.values())
                ptr_n = sum(1 for v in vals if v["has_ptr"] is True)
                bl_n = sum(1 for v in vals if v["in_dnsbl"])
                known_ip = sum(1 for v in vals if v["exit_ip"])
                dirty_n = sum(1 for v in vals if v.get("rdns_dirty"))
                outlook_n = sum(1 for v in vals if v.get("outlook_ok") is True)

                lats = sorted(v["latency_ms"] for v in vals if v.get("latency_ms"))
                if lats:
                    median = lats[len(lats) // 2]
                    self.callbacks['on_log'](
                        f"[INFO] Скорость прокси: медиана {median} мс, "
                        f"быстрейший {lats[0]} мс, медленнейший {lats[-1]} мс.", "info")

                self.callbacks['on_log'](
                    f"[INFO] Профиль готов: выходной IP определён у {known_ip} из "
                    f"{len(live_proxies)}, с PTR — {ptr_n}, в чёрных списках — {bl_n}.", "info")

                if outlook_n is not None:
                    self.callbacks['on_log'](
                        f"[INFO] Microsoft реально принял {outlook_n} прокси из "
                        f"{len(live_proxies)} (проверено пробой до MAIL FROM, "
                        "а не по спискам).", "info")
                if dirty_n:
                    self.callbacks['on_log'](
                        f"[DEAD] У {dirty_n} прокси имя в PTR выдаёт прокси/VPN/динамику "
                        "(proxy, vpn, tor, pool...). Почтовики такие штрафуют даже "
                        "при валидном обратном DNS.", "dead")

                from core.proxy_profile import provider_fitness
                fitness = provider_fitness(proxy_profiles)
                yahoo_ok = int((fitness.get("Yahoo / AOL") or {}).get("ok", 0))
                outlook = fitness.get("Outlook / Hotmail") or {}
                outlook_ok = int(outlook.get("ok", 0))

                if yahoo_ok:
                    self.callbacks['on_log'](
                        f"[INFO] Yahoo/AOL пойдут через {yahoo_ok} прокси, которые "
                        "Yahoo пустил на пробе.", "info")
                elif ptr_n:
                    self.callbacks['on_log'](
                        f"[DEAD] PTR есть у {ptr_n} прокси, но Yahoo на пробе не "
                        "пустил ни один — адреса Yahoo, AOL и Verizon останутся "
                        "недоказанными.", "dead")
                else:
                    self.callbacks['on_log'](
                        "[DEAD] Обратного DNS (PTR) нет ни у одного прокси — Yahoo, AOL "
                        "и Verizon проверить не получится. Остальные домены проверятся.", "dead")

                if outlook_ok:
                    self.callbacks['on_log'](
                        f"[INFO] Outlook/Hotmail пойдут через {outlook_ok} прокси, "
                        "которые Microsoft пустил на пробе.", "info")
                else:
                    self.callbacks['on_log'](
                        "[DEAD] Для Outlook/Hotmail нет ни одного прокси, который "
                        "Microsoft пустил бы на пробе (отказ, чёрный список или "
                        "прокси-имя в PTR: %d, не выяснено: %d) — их адреса "
                        "останутся недоказанными. "
                        "Нужен чистый IP." % (int(outlook.get("no", 0)),
                                              int(outlook.get("unknown", 0))),
                        "dead")

                try:
                    from core.proxy_profile import readiness_report
                    ready = readiness_report(proxy_profiles)
                    self.callbacks['on_log'](
                        ("[INFO] Готовность прокси: %s" if ready["ready"]
                         else "[DEAD] Готовность прокси: %s") % ready["verdict"],
                        "info" if ready["ready"] else "dead")
                    for item in ready["providers"]:
                        if not item["ok"]:
                            self.callbacks['on_log'](
                                "[DEAD]    %s — 0 годных прокси: %s"
                                % (item["name"], item["reason"]), "dead")
                except Exception:
                    pass

                if 'on_proxy_profile' in self.callbacks:
                    try:
                        from core.proxy_profile import pool_summary
                        self.callbacks['on_proxy_profile'](pool_summary(proxy_profiles))
                    except Exception:
                        pass
            except Exception as e:
                self.callbacks['on_log'](
                    "[DEAD] Профилирование прокси не удалось: %s: %s. "
                    "Выходной IP, PTR и чёрные списки не узнаны ни у одного "
                    "прокси — Yahoo/AOL и Outlook/iCloud пойдут вслепую."
                    % (type(e).__name__, e), "dead")
        return proxy_profiles
    def _block_run(self, reason):
        self.blocked_reason = reason
        self._stop_requested = True

    def _check_port25_direct(self):
        from core.port25 import probe_port25
        try:
            итог = probe_port25()
        except Exception:
            return
        if итог.get("verdict") == "closed":
            self.callbacks['on_log'](
                "[DEAD] С этого компьютера закрыт исходящий порт 25: ни один из "
                "%d почтовых серверов не ответил, хотя обычный интернет работает. "
                "Без прокси проверить нельзя ни одного ящика — прогон остановлен. "
                "Нужен прокси или VPS с открытым портом 25 "
                "(tools/make_vps_proxy.py)." % итог.get("tried", 0), "dead")
            self._block_run("порт 25 закрыт")
            return
        if итог.get("verdict") == "open":
            self.callbacks['on_log'](
                "[INFO] Порт 25 открыт: Gmail и Яндекс ответят честно; Yahoo, AOL, "
                "Outlook и iCloud без прокси с обратным DNS и чистой репутацией "
                "почти наверняка откажут.", "info")
        self.callbacks['on_log'](
            "[INFO] Без прокси второе мнение о «Годен» невозможно: второго "
            "выходного адреса нет. «Годен» держится на одной сессии и "
            "контрольной пробе выдуманным адресом.", "info")

    def setup(self, timeout=5, enable_ai=False, proxies=None, threads=100, use_cache=True):
        self.network = None
        self.blocked_reason = ""
        proxies_requested = bool(proxies)

        if not proxies_requested:
            self._stage("port25")
            self._check_port25_direct()
            if self._stop_requested:
                return
        self.callbacks['on_log']("[INFO] Подготовка валидатора (гибридный режим: Whitelist + DNS)...", "info")

        self._stage("cache")
        self.cache = None
        self._cache_hits = 0
        if use_cache:
            try:
                from core.settings import cache_path
                chosen = cache_path()
                cache = ResultCache(path=chosen)
                if cache.enabled:
                    dropped = cache.purge_expired()
                    self.cache = cache
                    msg = f"[INFO] Кэш вердиктов: {cache.size()} адресов из прошлых прогонов."
                    from core.cache import DEFAULT_CACHE_PATH
                    if chosen != DEFAULT_CACHE_PATH:
                        msg += f" Общий кэш: {chosen}."
                    if dropped:
                        msg += f" Просроченных удалено: {dropped}."
                    self.callbacks['on_log'](msg, "info")
                else:
                    self.callbacks['on_log'](
                        "[DEAD] Кэш вердиктов недоступен (не удалось открыть базу) — "
                        "проверяю всё заново.", "dead")
            except Exception as e:
                self.callbacks['on_log'](
                    f"[DEAD] Кэш вердиктов не включён ({type(e).__name__}).", "dead")
        
        self._stage("lists")
        try:
            self.callbacks['on_log']("[INFO] Проверка обновлений disposable-списков...", "info")
            BlacklistDownloader().download_all(log_callback=self.callbacks['on_log'])
        except Exception as e:
            self.callbacks['on_log'](f"[DEAD] Обновление списков не удалось ({type(e).__name__}), использую локальные.", "dead")
        if getattr(self, "_stop_requested", False):
            return

        self._stage("filters")
        try:
            free_path = data_path("free_providers.txt")
            if os.path.exists(free_path):
                with open(free_path, "r", encoding="utf-8") as f:
                    added = extend_free_domains(line.strip() for line in f
                                                if line.strip() and not line.startswith("#"))
                if added:
                    self.callbacks['on_log'](
                        f"[INFO] Бесплатных почтовиков добавлено: {added}. "
                        "Скоринг больше не путает их с корпоративными.", "info")
        except Exception:
            pass

        try:
            self.filter = SpamFilter(log_callback=self.callbacks.get('on_log'))
            self.callbacks['on_log'](f"[INFO] SpamFilter загружен ({self.filter.get_count() if hasattr(self.filter, 'get_count') else '?'} доменов).", "info")
            try:
                from core.disposable import extend_disposable_domains, get_disposable_count
                added = extend_disposable_domains(self.filter.blacklist_domains)
                if added:
                    self.callbacks['on_log'](
                        f"[INFO] В базу одноразовых добавлено {added} доменов "
                        f"(всего {get_disposable_count()}), поддомены тоже ловятся.", "info")
            except Exception:
                pass
        except Exception:
            self.filter = None
        
        if timeout > 30:
            self.callbacks['on_log'](
                f"[DEAD] Таймаут {timeout}с очень большой — прогон будет медленным. "
                "Обычно хватает 10-20с. (Зависнуть на одном адресе валидатор не даст: "
                "есть общий дедлайн, максимум 180с на адрес.)", "dead")

        proxy_profiles = {}
        if proxies:
            from core.network import filter_live_proxies, dedupe_proxies_stream
            proxies = dedupe_proxies_stream(proxies)
            ipv6_seen = [0]
            proxies = _count_ipv6_proxies(proxies, ipv6_seen)
            self._stage("proxies")
            self.callbacks['on_log'](
                f"[INFO] Тестирование прокси-серверов потоком "
                f"(потоков: {threads}, таймаут: {timeout}с)...", "info")
            proxy_progress = self.callbacks.get('on_proxy_progress')
            try:
                from core.settings import get as setting
                enough = int(setting("proxy_enough", 0) or 0)
            except Exception:
                enough = 0

            if getattr(self, "_stop_requested", False):
                return
            live_proxies, total_seen = filter_live_proxies(
                proxies, timeout=timeout, threads=threads,
                progress_callback=proxy_progress,
                log_callback=self.callbacks.get('on_log'),
                enough=max(0, enough),
                should_stop=lambda: getattr(self, "_stop_requested", False))
            if getattr(self, "_stop_requested", False):
                self.callbacks['on_log'](
                    "[INFO] Перебор прокси прерван «Стопом»: прочитано %d, живых %d."
                    % (total_seen, len(live_proxies)), "info")
                return
            share = (100.0 * len(live_proxies) / total_seen) if total_seen else 0.0
            self.callbacks['on_log'](
                "[INFO] Проверка прокси закончена: живых %d из %d (%.1f%%)."
                % (len(live_proxies), total_seen, share), "info")
            _warn_ipv6_unreachable(self.callbacks['on_log'], ipv6_seen[0])
            if 'on_proxies_tested' in self.callbacks:
                self.callbacks['on_proxies_tested'](len(live_proxies), total_seen)
            if not live_proxies:
                self.callbacks['on_log'](
                    "[DEAD] Ни один прокси не отвечает на порт 25. Проверять "
                    "почту через них нечем: почтовые серверы слушают именно "
                    "этот порт, а 587 и 465 к проверке ящиков отношения не "
                    "имеют. Вердиктов не будет — ни одного. Возьми прокси с "
                    "открытым портом 25 или подними свой VPS "
                    "(tools/make_vps_proxy.py), либо запусти без прокси и "
                    "проверь хотя бы Gmail и Яндекс. Прогон остановлен: идти "
                    "напрямую без твоего согласия нельзя — это раскрыло бы "
                    "домашний IP.", "dead")
                self._block_run("ни один прокси не ожил")
            elif len(live_proxies) < 10:
                self.callbacks['on_log'](
                    "[DEAD] Живых прокси всего %d. На большой базе этого мало: "
                    "почтовик считает нагрузку по адресу отправителя, и с "
                    "нескольких IP он быстро начнёт отвечать «слишком часто» "
                    "или принимать любые адреса подряд." % len(live_proxies),
                    "dead")
            proxies = live_proxies

            self.network = NetworkValidator(timeout=timeout, proxies=proxies)
            self._share_abort_event()
            if getattr(self, "_stop_requested", False):
                return
            if live_proxies:
                self._stage("profiles")
            proxy_profiles = self._profile_live_proxies(
                live_proxies, timeout, threads)

        if self.network is None:
            self.network = NetworkValidator(timeout=timeout, proxies=proxies)
            self._share_abort_event()
        self.activity.set_net_budget(net_budget(
            timeout, getattr(self.network, "address_deadline", 180)))


        resolvers = []
        try:
            from core.settings import spamhaus_resolvers
            resolvers = spamhaus_resolvers()
        except Exception:
            resolvers = []

        def включить_spamhaus():
            try:
                if resolvers and self.network:
                    if self.network.set_spamhaus_resolver(resolvers):
                        self.callbacks['on_log'](
                            f"[INFO] Spamhaus ZEN подключён через {', '.join(resolvers)} — "
                            "санитарный контракт зоны пройден.", "info")
                    else:
                        try:
                            why = self.network.spamhaus_refusal_reason()
                        except Exception:
                            why = "зона не прошла санитарный контракт"
                        self.callbacks['on_log'](
                            "[DEAD] Spamhaus ZEN не опрашивается через %s: %s "
                            "Проверяю без него — это значит, что крупнейший чёрный "
                            "список молчит, и репутация IP оценивается по семи "
                            "остальным зонам." % (", ".join(resolvers), why), "dead")
                elif not resolvers and self.network:
                    # 127.255.255.254, 8.8.8.8 — NXDOMAIN даже на обязательную
                    found = None
                    try:
                        found = self.network.autodetect_spamhaus_resolver()
                    except Exception:
                        found = None
                    if found:
                        self.callbacks['on_log'](
                            "[INFO] Spamhaus ZEN подключён сам через системный "
                            "резолвер %s — санитарный контракт зоны пройден." % found,
                            "info")
                    else:
                        self.callbacks['on_log'](
                            "[DEAD] Spamhaus ZEN не опрашивается: ни один резолвер из "
                            "системных зона не обслуживает. Крупнейший чёрный список "
                            "сейчас не участвует в оценке — репутация IP считается по "
                            "семи остальным зонам. Свой резолвер указывается в "
                            "data/settings.json полем spamhaus_resolvers; проще всего "
                            "поднять его на том же VPS, где стоит прокси.", "dead")
            except Exception:
                pass

        threading.Thread(target=включить_spamhaus, name="spamhaus-setup",
                         daemon=True).start()

        if self.cleaner is not None:
            self.cleaner.установить_проверку_домена(self._домен_принимает_почту)

        if getattr(self, "_stop_requested", False):
            return
        if proxy_profiles:
            self.network.set_proxy_profiles(proxy_profiles)
            self._start_profile_refresher(timeout=timeout, workers=threads)
        
        if getattr(self, "_stop_requested", False):
            return
        if enable_ai:
            self._stage("ai")
            self.callbacks['on_log']("[INFO] Прогрев и обучение Нейросети (TensorFlow + NaiveBayes)...", "info")
            self.ai = EmailAI()
            self.ai.train_models()
            self.callbacks['on_log']("[INFO] ИИ успешно обучен и готов к бою!", "info")
