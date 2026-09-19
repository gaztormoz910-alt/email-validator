# -*- coding: utf-8 -*-
"""Пересмотр уже выданного вердикта: канарейка, второе мнение, отзыв из кэша.

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ. Это единственное место, где программа ЗАБИРАЕТ
назад то, что уже сказала: домен раскрылся как catch-all в середине
прогона, канарейка уличила сервер, второй выход не подтвердил «Годен».
Такие правки обязаны читаться вместе и целиком — разбросанные по большому
файлу, они выглядят как частные случаи, а это один механизм.
"""
from core.canary import canary_address

__all__ = ["VerdictRevisionMixin"]


class VerdictRevisionMixin:
    def _second_opinion_on_valid(self, email, res):
        """Спрашивает адрес вторым выходом. True/False/None — см. сеть.

        Тихо: сбой второго мнения не должен ронять вердикт, полученный
        первым. None здесь означает «сверить не удалось», и первый ответ
        остаётся в силе — иначе наш собственный сбой понижал бы честно
        подтверждённые адреса.
        """
        if self.network is None:
            return None
        mx = res.get("mx_records") or ([res["mx_record"]]
                                       if res.get("mx_record") else [])
        if not mx:
            return None
        try:
            return self.network.confirm_valid_from_other_exit(
                email, list(mx), first_proxy=res.get("proxy"))
        except Exception:
            return None
    def _fly_canary(self, email, res):
        """Пускает канарейку по домену только что подтверждённого адреса.

        Тихо и не чаще одного раза на пару «выход + домен» за прогон: лишняя
        сессия к чужому почтовику — лишний повод попасться ему на глаза,
        ровно за тем ответом, ради которого мы и пришли.
        """
        watch = getattr(self, "canary", None)
        if watch is None or self.network is None:
            return False
        try:
            domain = email.rsplit("@", 1)[1].lower()
        except Exception:
            return False
        proxy = res.get("proxy")
        try:
            exit_ip = self.network.exit_ip_of(proxy) if proxy else None
        except Exception:
            exit_ip = proxy
        exit_ip = exit_ip or proxy

        watch.note_valid(exit_ip, domain)
        if not watch.should_probe(exit_ip, domain):
            return False

        mx = res.get("mx_records") or ([res["mx_record"]]
                                       if res.get("mx_record") else [])
        if not mx:
            return False
        try:
            ответ = self.network.stealth_smtp_ping(
                canary_address(domain), list(mx), prefer_exit_of=proxy)
            статус = ответ.get("status")
        except Exception:
            # Сорвавшаяся проба — это НЕ улика. Молчим: обвинить выход по
            # своему же сбою значит выбросить живые адреса.
            return False

        if not watch.record(exit_ip, domain, статус):
            return False

        self.callbacks['on_log'](
            "[DEAD] Канарейка вернулась живой: %s принял заведомо "
            "несуществующий адрес с выхода %s. Все «Годен» по этому домену с "
            "этого выхода НЕДОКАЗУЕМЫ — виноват прокси, не база."
            % (domain, exit_ip or "прямого соединения"), "dead")
        return True
    def _forget_cached(self, domains, why):
        """Стирает из кэша вердикты по разоблачённым доменам.

        `_revise` чинит ТЕКУЩИЙ прогон: таблицу и выгрузку. Но вердикт лежит
        ещё и в кэше со сроком в тридцать суток, и следующий запуск достанет
        оттуда тот самый «Годен», не сходив в сеть. Разоблачение действовало
        бы один прогон, а ложный вердикт возвращался бы на месяц — то есть
        владелец получил бы его ровно тогда, когда уже забыл про
        предупреждение.

        Тихо и по одному домену: сбой кэша не имеет права ронять прогон,
        который к этому моменту уже закончен.
        """
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
    def _revise(self, domains, new_status, note):
        """Просит поверхность пересмотреть уже показанные строки по домену.

        Канал необязательный: командная строка и API держат свои списки, и
        каждый пересматривает их сам. Отсутствие обработчика не должно ронять
        прогон — но и молчать об этом нельзя, поэтому строка в логе остаётся
        в любом случае (её пишет вызывающий).
        """
        handler = self.callbacks.get('on_revise')
        if handler is None or not domains:
            return 0
        try:
            return int(handler(list(domains), str(new_status), str(note)) or 0)
        except Exception:
            return 0
