# -*- coding: utf-8 -*-
"""Подготовка прогона: сеть, кэш, списки, отбор и профилирование прокси.

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ. `setup` и профилирование прокси — это всё, что
происходит ДО первого адреса: создаётся валидатор, поднимается кэш,
докачиваются чёрные списки, отбираются живые прокси и снимается их профиль.
Ни одна из этих строк не участвует в разборе конкретного адреса, но лежали
они посреди файла, где разбирается каждый.

ПОЧЕМУ ПРИМЕСЬ. Всё состояние заводится в `ValidationPipeline.__init__` и
остаётся там же. Примесь работает с тем же объектом: файл поделён,
поведение — нет.
"""
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

__all__ = ["PipelineSetupMixin"]


class PipelineSetupMixin:
    def _домен_принимает_почту(self, domain):
        """True / False / None — принимает ли домен почту.

        Обёртка над get_mx_records, сохраняющая три состояния. Различие между
        «записей нет» и «спросить не удалось» здесь решает, подменим мы адрес
        владельца или нет, поэтому схлопывать их нельзя ни в коем случае.

        Своей памяти не заводит намеренно: get_mx_records уже кэширует ответ
        на прогон, а вторая копия кэша разошлась бы с первой.
        """
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
        """Прокси для HTTP-проверок (Gravatar, RDAP, HEAD).

        Возвращает None, если прокси не заданы — тогда идём напрямую, как раньше.
        Если заданы, все HTTP-каналы идут через них: иначе реальный IP утекает
        и на gravatar.com, и в WHOIS, и на сайт самой проверяемой компании.
        """
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
        """Фоновое обновление профиля прокси раз в interval секунд."""
        self._refresh_stop = threading.Event()

        def loop():
            while not self._refresh_stop.wait(interval):
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
    def _stop_profile_refresher(self):
        stop = getattr(self, "_refresh_stop", None)
        if stop is not None:
            stop.set()
    def _profile_live_proxies(self, live_proxies, timeout, threads):
        """Профиль пула: реальный выходной IP, обратный DNS, чёрные списки.

        Выходной IP спрашиваем у самого Gmail (он сообщает его в ответе на
        EHLO) — стороннего сервиса не нужно. Проверять надо именно ЕГО:
        адрес подключения к прокси совпадает с выходным не всегда.

        Живёт отдельным методом не ради красоты. Внутри блок обёрнут в
        `except Exception` — то есть ЛЮБАЯ поломка здесь превращается в одну
        строку лога и молчаливую потерю всего профиля пула. Пока блок сидел
        внутри setup(), проверить его отдельно было нечем, и он падал
        каждый прогон, ничего об этом не сообщая по существу.

        Требует УЖЕ созданный self.network: профили с прошлого запуска
        спрашиваются у него.
        """
        # Профилируем прокси: реальный выходной IP, обратный DNS, чёрные списки.
        # Выходной IP спрашиваем у самого Gmail (он сообщает его в ответе на
        # EHLO) — стороннего сервиса не нужно. Проверять надо именно ЕГО:
        # адрес подключения к прокси совпадает с выходным не всегда.
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

                # Профили, снятые в прошлый раз, подставляются сразу.
                #
                # Снятие — это выходной IP через EHLO у Gmail, обратный
                # DNS, семь чёрных списков и три прямые пробы почтовиков
                # НА КАЖДЫЙ прокси. На пуле в несколько сотен — минуты
                # простоя перед каждой работой, а выходной адрес за сутки
                # обычно не меняется. Заново снимаем только тех, кого не
                # помним; фоновое обновление всё равно идёт раз в десять
                # минут и поправит то, что успело устареть.
                remembered = self.network.recall_proxy_profiles(live_proxies)
                fresh_needed = [p for p in live_proxies if p not in remembered]
                if remembered:
                    self.callbacks['on_log'](
                        "[PROXY] Из прошлого запуска помню профиль %d прокси "
                        "из %d — заново проверяю только остальных."
                        % (len(remembered), len(live_proxies)), "info")

                # Потоки берём из ползунка: раньше здесь было жёсткое 30, и
                # список в несколько тысяч прокси профилировался часами.
                proxy_profiles = dict(remembered)
                if fresh_needed:
                    proxy_profiles.update(profile_proxies(
                        fresh_needed, timeout=timeout, workers=threads,
                        progress_callback=on_prof))

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

                # Годные считаются ТЕМ ЖЕ правилом, что и «Готовность прокси»
                # ниже (core/proxy_profile.py): прямой ответ почтовика главнее
                # признаков. Раньше здесь считались «есть PTR» и «нет в
                # чёрных списках», и журнал противоречил сам себе через две
                # строки. Замерено прогоном 27.09.2026 на списке владельца:
                # «Outlook/iCloud/GMX пойдут через 16 прокси», а ниже —
                # «Outlook / Hotmail — 0 годных прокси»: Microsoft на пробе не
                # пустил ни один из 21.
                from core.proxy_profile import provider_fitness
                fitness = provider_fitness(proxy_profiles)
                yahoo_ok = int((fitness.get("Yahoo / AOL") or {}).get("ok", 0))
                outlook = fitness.get("Outlook / Hotmail") or {}
                outlook_ok = int(outlook.get("ok", 0))

                if yahoo_ok:
                    self.callbacks['on_log'](
                        f"[INFO] Yahoo/AOL пойдут через {yahoo_ok} прокси с PTR.", "info")
                elif ptr_n:
                    # PTR есть, а годных ноль — значит, Yahoo на пробе отказал
                    # каждому из них: без прямого отказа прокси с PTR годен.
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
                    # Числа причин — из той же оценки: «отказ» — Microsoft
                    # не пустил, IP в чёрных списках или имя PTR выдаёт
                    # прокси; «не выяснено» — пробы не было. Ни то ни другое
                    # годным не считается.
                    self.callbacks['on_log'](
                        "[DEAD] Для Outlook/Hotmail нет ни одного прокси, который "
                        "Microsoft пустил бы на пробе (отказ, чёрный список или "
                        "прокси-имя в PTR: %d, не выяснено: %d) — их адреса "
                        "останутся недоказанными. "
                        "Нужен чистый IP." % (int(outlook.get("no", 0)),
                                              int(outlook.get("unknown", 0))),
                        "dead")

                # Структурная сводка для окна. Всё перечисленное выше уже
                # уходило строками лога, но лог прокручивается и теряется,
                # а решение «хватит ли этих прокси» пользователь принимает
                # именно по этим числам. Считает их core/proxy_profile.py,
                # чтобы панель, лог и CLI не могли разойтись.
                # Готовность — до прогона, а не после.
                #
                # Раньше владелец узнавал, что прокси не годятся, из
                # сплошного «не доказано» через полчаса работы. Причина
                # при этом лежала в одной строке профиля, которую никто
                # не читал. Теперь она произносится вслух и с указанием,
                # что чинить.
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
        """Остановить прогон ДО первого адреса и сказать почему.

        run_pipeline видит _stop_requested в самом начале и заканчивает, не
        тронув ни одного адреса. blocked_reason читают окно и командная
        строка, чтобы не выдать пустой результат за законченную проверку.
        """
        self.blocked_reason = reason
        self._stop_requested = True

    def _check_port25_direct(self):
        """Прямой режим: открыт ли исходящий порт 25. Закрыт — прогона не будет."""
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
        # Второе мнение о «Годен» спрашивается с ДРУГОГО выходного адреса, а
        # без прокси он один. Настройка включена всегда, и молчать о том, что
        # здесь она не работает, значило бы выдавать одну сессию за две.
        self.callbacks['on_log'](
            "[INFO] Без прокси второе мнение о «Годен» невозможно: второго "
            "выходного адреса нет. «Годен» держится на одной сессии и "
            "контрольной пробе выдуманным адресом.", "info")

    def setup(self, timeout=5, enable_ai=False, proxies=None, threads=100, use_cache=True):
        # Прогон начинается с чистой сети: донашивать объект от прошлого
        # запуска нельзя — у него внутри старый список прокси.
        self.network = None
        self.blocked_reason = ""
        # Прокси ЗАДАНЫ владельцем — это решение, и после перебора оно не
        # меняется: даже если ни один не ожил, идти напрямую нельзя.
        proxies_requested = bool(proxies)

        # Прямой режим: сначала убедиться, что проверять вообще есть чем, —
        # ДО скачивания списков и загрузки фильтров. Закрытый порт иначе
        # выяснялся бы через минуту подготовки, которая всё равно впустую.
        if not proxies_requested:
            self._stage("port25")
            self._check_port25_direct()
            if self._stop_requested:
                return
        # Гибридный режим: Whitelist + DNS-проверка неизвестных доменов
        self.callbacks['on_log']("[INFO] Подготовка валидатора (гибридный режим: Whitelist + DNS)...", "info")

        # Кэш вердиктов прошлых прогонов. Хранит только доказанное — Valid и
        # Invalid/Bounce; Unknown и Risky не кэшируются никогда, иначе сбой
        # нашей стороны закрепился бы за адресом навсегда.
        self._stage("cache")
        self.cache = None
        self._cache_hits = 0
        if use_cache:
            try:
                # Путь из настроек: положив кэш в синхронизируемую папку
                # (OneDrive, сетевой диск), два рабочих места перестают
                # проверять одно и то же по второму разу.
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
        
        # Обновляем disposable/spam-списки ДО загрузки SpamFilter, чтобы он
        # сразу подхватил свежие данные. Списки переустанавливаются (замена, не
        # накопление), а качаются только если на сервере реально есть новое.
        self._stage("lists")
        try:
            self.callbacks['on_log']("[INFO] Проверка обновлений disposable-списков...", "info")
            BlacklistDownloader().download_all(log_callback=self.callbacks['on_log'])
        except Exception as e:
            self.callbacks['on_log'](f"[DEAD] Обновление списков не удалось ({type(e).__name__}), использую локальные.", "dead")
        # «Стоп» на подготовке: дальше не идём. Раньше подготовка проверяла
        # остановку только после порта 25 и доделывала всё — фильтры, полный
        # перебор прокси, профили, прогрев ИИ, — а окно всё это время писало
        # «Останавливаю» (рецензия 17.10.2026). run_pipeline увидит флаг и
        # закончит прогон, не тронув ни одного адреса.
        if getattr(self, "_stop_requested", False):
            return

        self._stage("filters")
        # Список бесплатных почтовиков. Он НЕ для отбраковки, а для скоринга:
        # без него сотни бесплатных сервисов считаются корпоративными и
        # получают +5, которого не получает gmail.com.
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

        # Подключаем SpamFilter из внешних файлов
        try:
            self.filter = SpamFilter(log_callback=self.callbacks.get('on_log'))
            self.callbacks['on_log'](f"[INFO] SpamFilter загружен ({self.filter.get_count() if hasattr(self.filter, 'get_count') else '?'} доменов).", "info")
            # Сливаем свежие списки во встроенную базу: она захардкожена и сама
            # не обновляется, зато умеет проверять ПОДДОМЕНЫ (foo.mailinator.com),
            # чего SpamFilter не делает — он сверяет только точное имя домена.
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
        
        # Высокий таймаут вместе с повторами через прокси даёт огромное время на
        # один адрес: до 10 попыток * таймаут. Ползунок не трогаем (это осознанная
        # настройка), но предупреждаем, иначе прогон выглядит как зависание.
        if timeout > 30:
            self.callbacks['on_log'](
                f"[DEAD] Таймаут {timeout}с очень большой — прогон будет медленным. "
                "Обычно хватает 10-20с. (Зависнуть на одном адресе валидатор не даст: "
                "есть общий дедлайн, максимум 180с на адрес.)", "dead")

        proxy_profiles = {}
        if proxies:
            from core.network import filter_live_proxies, dedupe_proxies_stream
            # Прокси приходят ЛЕНИВО: на входе может быть и список, и генератор
            # из файла в миллионы строк. Длину заранее не спрашиваем — это
            # прочитало бы весь вход в память ради одного числа.
            #
            # Повторы схлопываются по ходу чтения: один прокси, записанный
            # дважды, проверялся бы дважды и занимал два места в ротации.
            proxies = dedupe_proxies_stream(proxies)
            self._stage("proxies")
            self.callbacks['on_log'](
                f"[INFO] Тестирование прокси-серверов потоком "
                f"(потоков: {threads}, таймаут: {timeout}с)...", "info")
            # Теперь таймаут строго подчиняется твоему ползунку (никаких ограничений!)
            # Прогресс прокси идёт СВОИМ каналом, а не в полосу проверки почт.
            #
            # Раньше он шёл в on_progress — тот самый, которым потом двигается
            # проверка адресов. Владелец видел «Проверено 16 891 из 19 590»
            # рядом с карточками, где всюду нули, и читал это как почты. А
            # считались прокси, и «из» было не итогом, а «сколько прочитано на
            # сейчас»: разница между числами на девяти снимках подряд ровно
            # 2699 — постоянный отрыв читателя от проверяющего.
            proxy_progress = self.callbacks.get('on_proxy_progress')
            # «Хватит живых» — настройка владельца, по умолчанию выключена.
            # См. core/settings.py: на бесплатных списках перебор всего файла
            # съедает больше времени, чем сама проверка почт.
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
                # Ни «живых 0 из N» (это объявило бы прогон заблокированным,
                # хотя его остановили вы), ни профилей с прогревом ИИ.
                self.callbacks['on_log'](
                    "[INFO] Перебор прокси прерван «Стопом»: прочитано %d, живых %d."
                    % (total_seen, len(live_proxies)), "info")
                return
            # Итог перебора говорится числом И смыслом. «Найдено 54 из 26390»
            # само по себе не отвечает на вопрос, который у владельца в
            # голове: «а проверятся ли теперь мои почты».
            share = (100.0 * len(live_proxies) / total_seen) if total_seen else 0.0
            self.callbacks['on_log'](
                "[INFO] Проверка прокси закончена: живых %d из %d (%.1f%%)."
                % (len(live_proxies), total_seen, share), "info")
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
                # Раньше здесь только писалось «вердиктов не будет», а дальше
                # сеть создавалась с ПУСТЫМ списком прокси — то есть как прямое
                # соединение, и прогон тихо шёл с домашнего IP. Найдено при
                # внедрении аудита 27.09.2026.
                self._block_run("ни один прокси не ожил")
            elif len(live_proxies) < 10:
                self.callbacks['on_log'](
                    "[DEAD] Живых прокси всего %d. На большой базе этого мало: "
                    "почтовик считает нагрузку по адресу отправителя, и с "
                    "нескольких IP он быстро начнёт отвечать «слишком часто» "
                    "или принимать любые адреса подряд." % len(live_proxies),
                    "dead")
            proxies = live_proxies

            # Сеть создаётся ЗДЕСЬ, ДО профилирования, а не после него.
            # Профилирование спрашивает у неё профили, снятые в прошлый раз.
            # Пока объект создавался ниже, этот вызов падал с AttributeError
            # на КАЖДОМ прогоне: в логе оставалась одна строка «не удалось
            # (AttributeError)», а выходной IP, PTR и чёрные списки не
            # узнавались ни у одного прокси. Маршрутизация Yahoo/AOL (нужен
            # PTR) и Outlook/iCloud (нужна чистая репутация) после этого
            # работала вслепую.
            self.network = NetworkValidator(timeout=timeout, proxies=proxies)
            if getattr(self, "_stop_requested", False):
                return
            if live_proxies:
                self._stage("profiles")
            proxy_profiles = self._profile_live_proxies(
                live_proxies, timeout, threads)

        # Прокси не задавали — сеть ещё не создана, создаём здесь.
        if self.network is None:
            self.network = NetworkValidator(timeout=timeout, proxies=proxies)
        # Сколько может законно идти одна проверка при этом таймауте: по нему
        # журнал активности отличает долгую проверку от зависания.
        self.activity.set_net_budget(net_budget(
            timeout, getattr(self.network, "address_deadline", 180)))


        # Spamhaus ZEN — крупнейший чёрный список, и до сих пор он молчал.
        # Код опроса был написан и покрыт тестами, но включался только в них:
        # в рабочем прогоне резолвер никто не задавал, и зона не спрашивалась
        # вовсе. Причина не в лени, а в самом Spamhaus: публичные резолверы
        # он не обслуживает и отвечает NXDOMAIN даже на обязательную тестовую
        # запись. Нужен свой — на том же VPS, где стоит прокси.
        resolvers = []
        try:
            from core.settings import spamhaus_resolvers
            resolvers = spamhaus_resolvers()
        except Exception:
            resolvers = []

        # ВКЛЮЧАЕТСЯ В ФОНЕ, прогон её не ждёт. Замерено прогоном test_1.txt
        # владельца 27.09.2026 через его 1394 прокси: поиск резолвера занял
        # 186 с — и не нашёл ни одного, — а проверка адресов всё это время
        # стояла. Ждать незачем: профиль прокси уже снят выше, без Spamhaus,
        # а сама зона нужна фоновому обновлению профиля и оценке репутации
        # почтовых серверов. Пока резолвер ищется, зона отвечает «не
        # спрашивали» (None) — ровно как и когда он не найден вовсе.
        def включить_spamhaus():
            try:
                if resolvers and self.network:
                    if self.network.set_spamhaus_resolver(resolvers):
                        self.callbacks['on_log'](
                            f"[INFO] Spamhaus ZEN подключён через {', '.join(resolvers)} — "
                            "санитарный контракт зоны пройден.", "info")
                    else:
                        # Причина называется словами. «Не прошла контракт» не говорит
                        # владельцу, что чинить: отказ резолверу и недоступная сеть
                        # лечатся по-разному.
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
                    # Резолвер не задан — не повод молчать. Зона не обслуживает
                    # КРУПНЫЕ публичные резолверы, но в системном списке обычно лежит
                    # ещё и резолвер провайдера или Quad9, а их она обслуживает.
                    #
                    # Замерено на машине владельца: 1.1.1.1 отвечает кодом отказа
                    # 127.255.255.254, 8.8.8.8 — NXDOMAIN даже на обязательную
                    # тестовую запись, а 9.9.9.9 отвечает правильно. То есть
                    # крупнейший чёрный список был доступен всё это время — его просто
                    # никто не спросил.
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
                # Сбой поиска не должен ронять ничего: Spamhaus — одна из
                # восьми зон, а не условие работы.
                pass

        threading.Thread(target=включить_spamhaus, name="spamhaus-setup",
                         daemon=True).start()

        # Починка склейки домена теперь применяется только по ответу DNS.
        # Признак «к зоне приклеен мусор» одинаково подходит настоящей
        # склейке (`mail.ruxxx`) и чужому домену (`honda.carpoi`, где после
        # реза выходит правдоподобный `honda.car`). Отличить их строкой
        # нельзя — спрашиваем факт. Без этой строки очистка ведёт себя как
        # раньше, поэтому все её офлайновые проверки остаются в силе.
        if self.cleaner is not None:
            self.cleaner.установить_проверку_домена(self._домен_принимает_почту)

        if proxy_profiles:
            self.network.set_proxy_profiles(proxy_profiles)
            # Профиль протухает: у ротирующегося прокси выходной IP меняется
            # по ходу прогона, и маршрутизация продолжает считать, что PTR
            # на месте. Обновляем в фоне, чтобы не держать воркеры.
            self._start_profile_refresher(timeout=timeout, workers=threads)
        
        if getattr(self, "_stop_requested", False):
            return
        if enable_ai:
            self._stage("ai")
            self.callbacks['on_log']("[INFO] Прогрев и обучение Нейросети (TensorFlow + NaiveBayes)...", "info")
            self.ai = EmailAI()
            self.ai.train_models()
            self.callbacks['on_log']("[INFO] ИИ успешно обучен и готов к бою!", "info")
