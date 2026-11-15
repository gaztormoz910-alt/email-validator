# -*- coding: utf-8 -*-
"""Управление идущим прогоном: «Стоп» и пауза.

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ. core/pipeline.py стоит у потолка размера модуля
(tools/verify_module_sizes.py), а у остановки свой смысл и свои правила:
две разные остановки — «доделать начатое» (Ctrl+C в CLI) и «бросить
начатое» (кнопка «Стоп» в окне) — и пауза, которую остановка снимает.
"""

__all__ = ["RunControlMixin"]


class RunControlMixin:
    def stop(self, abort=False):
        """Остановка прогона. abort=True — бросить начатые проверки (окно).

        Без abort начатые адреса доделываются: так работает Ctrl+C в CLI
        («доделываю начатые»), и это обещание консоли не меняется.
        """
        if abort:
            # Сначала флаг, потом событие: поток, проснувшийся от события,
            # уже видит, что выдавать результат нельзя.
            self._aborting = True
            self._abort_event.set()
            network = getattr(self, "network", None)
            event = getattr(network, "abort_event", None)
            if event is not None and event is not self._abort_event:
                event.set()
            # Открытые SMTP-сессии закрываются: поток, ждущий ответа сервера,
            # иначе досиживал таймаут сессии (core/network_abort.py).
            close = getattr(network, "abort_connections", None)
            if callable(close):
                close()
            state = getattr(self, "state", None)
            freeze = getattr(state, "freeze", None)
            if callable(freeze):
                freeze()
        self._stop_requested = True
        self.is_running = False
        # До конца потока окно скажет «останавливаю», а не «работает».
        self.activity.request_stop()
        # Остановка снимает и паузу: иначе остановленный на паузе прогон
        # остаётся «на паузе» навсегда, и следующий запуск стартует замершим.
        self.is_paused = False
        self.activity.set_paused(False)
        # Фоновое обновление профилей прокси — тоже работа прогона. Раньше
        # после «Стопа» на подготовке оно жило до следующего пробуждения
        # (до 10 минут) и ходило в сеть.
        self._stop_profile_refresher()

    def _settle_resume_journal(self, state, resume, feeder_error):
        """Конец прогона: стереть журнал продолжения или сохранить его.

        ЛОВУШКА, закрытая здесь. RunState стирает память о прогоне ТОЛЬКО
        когда продолжение выключено (`if not resume: self.clear()` в
        core/runstate.py). Раз продолжение включено всегда и убрано из окна,
        память не стиралась бы никогда: второй запуск того же файла дал бы
        НОЛЬ адресов к проверке, а починить это было бы нечем — остаётся
        удалять sqlite руками. Поэтому память стирается сама после прогона,
        дошедшего до конца.

        Сохраняется после Ctrl+C в CLI (stop без броска) и после обрыва
        чтения базы: прогон до конца не дошёл, и следующий запуск обязан
        продолжить, а не проверять по сети заново всё уже проверенное
        (рецензия 17.10.2026).

        Стирается и после «Стопа» из окна (stop(abort=True)): окно стёрло
        таблицу, и продолжение пропустило бы выданное до «Стопа» — оно не
        появилось бы больше нигде. Следующий запуск той же базы проверит её
        заново, а готовые вердикты возьмёт из кэша без сети (рецензия
        07.11.2026). Отметки «сделано» стирает уже сам «Стоп» (freeze в
        core/runstate.py) — на случай, если окно закроют раньше, чем прогон
        доживёт до этой строки; здесь дочищается остальное.
        """
        try:
            if (resume and not self._stop_requested and not feeder_error) or self._aborting:
                state.clear()
        except Exception:
            pass

    def pause(self):
        self.is_paused = not self.is_paused
        # Пауза и возобновление — события для журнала активности: молчание
        # на паузе не должно после «Продолжить» читаться как зависание.
        self.activity.set_paused(self.is_paused)
        return self.is_paused
