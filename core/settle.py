# -*- coding: utf-8 -*-
"""Что происходит с адресом ПОСЛЕ ответа сервера — одинаково в обоих проходах.

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ. «Лестница после вердикта» (перевод статуса в
отображаемый, второе мнение о «Годен», канарейка, доля «Годен» по домену,
обогащение, выдача) жила в core/pipeline.py дважды: в основном проходе и в
круге перепроверки. Копии разошлись: перепроверка не звала ни второе мнение,
ни канарейку, и адрес, который в первый раз получил таймаут или серый
список, становился «Годен» без обеих защит. Аудит 27.09.2026 воспроизвёл это
на настоящем коде — сервер, принимающий любой адрес, выдал «Годен» на
выдуманный (D3). Теперь лестница одна, и разойтись ей не с чем.

Здесь же — ранние отказы без SMTP, которым нужен тот же выход наружу:
ловушка по имени ящика и одноразовый сервис по почтовому серверу.
"""
from core.cleaner import normalize_for_dedup
from core.disposable import disposable_mx_owner
from core.heuristics import trap_word_in_local
from core.verdict import verdict_confidence

__all__ = ["SettleMixin", "DISPLAY_OF", "SettleContext"]


# Сырой статус проверки -> то, что видит владелец. Всё незнакомое — «не
# проверено», а не приговор: незнакомое слово — это отсутствие
# доказательства, а не доказательство отсутствия.
DISPLAY_OF = {
    "valid": "Valid",
    "invalid": "Invalid/Bounce",
    "risky": "Risky",
    "unknown": "Unknown",
    # Домен принимает любой адрес — существование ящика не выясняется.
    "catchall": "Unknown",
    # Ящик есть, но письмо не дойдёт. Группа «Не слать», не «Мёртв».
    "full": "Mailbox Full",
    "disabled": "Disabled",
    # Сервер принял, но приём любых адресов не исключён (core/confirmation.py).
    "unconfirmed": "Unconfirmed",
    "trap": "Trap/Disposable",
    "disposable": "Trap/Disposable",
    # Сюда серый список доходит только в последнем круге: ответа так и нет.
    "greylisted": "Risky",
}


class SettleContext(object):
    """Общее состояние прогона, нужное лестнице: статистика доменов и журнал."""

    __slots__ = ("domain_stats", "lock", "state")

    def __init__(self, domain_stats, lock, state):
        self.domain_stats = domain_stats
        self.lock = lock
        self.state = state


class SettleMixin:
    """Лестница после вердикта и ранние отказы. Примешивается к конвейеру."""

    # ── ранние отказы: адрес не уходит в SMTP ──────────────────────────

    def _emit_trap(self, email, data, reason, provider_type, basis_status,
                   enable_ai, mx="N/A"):
        """Выдача «Не слать» для ловушек и одноразовых, найденных не по домену."""
        data["engagement_score"] = 0
        data["engagement_grade"] = "Dead"
        data["provider_type"] = provider_type
        уверенность, основание = verdict_confidence(basis_status, reason)
        data["verdict_confidence"] = уверенность
        data["verdict_basis"] = основание
        self._enrich_offline(email, data, "Trap/Disposable", enable_ai)
        self._emit(email, "Trap/Disposable", reason, mx, data)

    def _trap_by_name(self, email, data, enable_ai):
        """`spamtrap@`, `honeypot@` и подобные — адрес-ловушка по самому имени.

        Такие ящики заводят затем, чтобы ловить рассылку по собранным базам:
        письмо туда — прямой удар по репутации отправителя. ZeroBounce
        помечает их possible_trap. Проверка строгая, по целым словам имени:
        `trapeznikov@` ловушкой не считается.
        """
        слово = trap_word_in_local(email)
        if not слово:
            return False
        self._emit_trap(email, data,
                        "Имя ящика похоже на ловушку для рассылок («%s») — "
                        "писать нельзя" % слово,
                        "Ловушка по имени", "trap", enable_ai)
        return True

    def _disposable_by_mx(self, email, data, enable_ai):
        """Одноразовый сервис, узнанный по почтовому серверу, а не по домену.

        Новые домены одноразовых сервисов появляются каждый день, а списки
        отстают; зато садятся новые домены на те же почтовые серверы. Если MX
        домена принадлежит известному одноразовому сервису, домен — его, как
        бы он ни назывался (у Verifalia это MailExchangerIsWellKnownDea).

        Тихо: сбой DNS здесь не повод ничего решать — адрес пойдёт в SMTP.
        """
        спросить = getattr(self.network, "get_mx_records", None)
        if спросить is None or "@" not in email:
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

    # ── подсказка опечатки при живом MX ─────────────────────────────────

    def _typo_hint_on_live_mx(self, email, data, res, fix_typos):
        """Домен похож на опечатку популярного почтовика, а MX у него есть.

        Такие домены (`gamil.com`, `gmai.com`, `gnail.com`) — классические
        ловушки для опечаток. Статус НЕ меняется: в словаре опечаток есть и
        настоящие домены организаций (`mai.ru` — МАИ), и понижение хоронило бы
        их живые адреса. Но если сервер не дал «Годен» (принимает всё, молчит),
        владелец должен видеть, что человек, скорее всего, метил в другой
        домен. Подтверждённый «Годен» не трогается: честный сервер, который
        отверг выдуманный адрес и принял этот, — не ловушка.
        """
        if res.get("status") not in ("catchall", "unknown", "risky", "unconfirmed"):
            return
        if data.get("suggested_email"):
            return
        self._подсказать_опечатку(email, data, fix_typos)
        подсказка = data.get("suggested_email")
        if подсказка:
            res["reason"] = "%s | Похоже на опечатку: имелся в виду %s?" % (
                res.get("reason", ""), подсказка.rsplit("@", 1)[1])

    # ── лестница после вердикта ─────────────────────────────────────────

    def _settle(self, email, data, is_role, res, enable_ai, ctx):
        """Переводит ответ проверки в строку выдачи. Один путь для обоих проходов."""
        raw_status = res.get("status", "unknown")
        status_display = DISPLAY_OF.get(raw_status, "Unknown")

        dom_key = email.rsplit("@", 1)[1].lower() if "@" in email else ""
        if dom_key:
            with ctx.lock:
                st = ctx.domain_stats.setdefault(dom_key, {"total": 0, "valid": 0})
                st["total"] += 1
                if raw_status == "valid":
                    st["valid"] += 1

        # Второе мнение о «Годен» — с ДРУГОГО выходного адреса. Расхождение
        # понижает до «Неясно», а не до приговора: отвергнуть могли по
        # репутации второго выхода. Без прокси второго выхода нет, и это
        # записывается в основание уверенности, а не замалчивается.
        if raw_status == "valid" and getattr(self, "confirm_valid", False):
            итог = self._second_opinion_on_valid(email, res)
            if итог is False:
                raw_status = "unknown"
                status_display = "Unknown"
                res["status"] = "unknown"
                res["reason"] = ("Второй выход отверг адрес, первый принял — "
                                 "доказательства нет ни у одной стороны")
            elif итог is None:
                res["valid_second_opinion"] = "unavailable"
            else:
                res["valid_second_opinion"] = "agreed"

        # Канарейка: заведомо мёртвый адрес отдельной пробой. Ловит
        # тарпитинг, включившийся посреди прогона, и зазор у гигантов.
        if raw_status == "valid":
            self._fly_canary(email, res)

        if dom_key:
            with ctx.lock:
                st = ctx.domain_stats.get(dom_key) or {}
            всего = int(st.get("total") or 0)
            if всего:
                data["domain_valid_ratio"] = round(int(st.get("valid") or 0) / float(всего), 3)
                data["domain_checked"] = всего

        # Что именно ушло в RCPT TO — строка «Проверен как» в карточке.
        try:
            data["checked_as"] = (self.network.probe_form(email)
                                  if self.network is not None else email)
        except Exception:
            data["checked_as"] = email

        # Ролевой адрес — ПРИЗНАК, а не вердикт. «Role-based» показывается
        # только у ДОКАЗАННО живого ролевого ящика: он по-прежнему «Не слать».
        # Мёртвый info@ теперь «Мёртв», непроверенный — «Неясно» (аудит, D8):
        # раньше все три выглядели одинаково, и для B2B-рассылки нельзя было
        # отобрать живые ролевые адреса и выбросить мёртвые.
        original_smtp_status = status_display
        data["role_address"] = bool(is_role)
        if is_role and status_display == "Valid":
            status_display = "Role-based"

        self._enrich_and_score(email, data, res, status_display,
                               original_smtp_status, is_role, enable_ai)
        self._emit(email, status_display, res.get("reason", ""),
                   res.get("mx_record", "N/A"), data)
        ctx.state.mark_done(normalize_for_dedup(email))
