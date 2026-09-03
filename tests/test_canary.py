# -*- coding: utf-8 -*-
"""Канарейки: ловят врущий почтовик, но не хоронят живые адреса.

Контрольная проба спрашивает выдуманный адрес в ТОЙ ЖЕ сессии и ловит
catch-all — постоянное свойство домена. Канарейка ловит то, чего та не
видит:

  * тарпитинг, включившийся ПОСРЕДИ прогона (первые двести адресов домена
    проверены честно, на двести первом почтовик решил, что идёт перебор);
  * зазор у гигантов, где контрольная проба идёт раз в 25 адресов на домен.

Половина проверок здесь — про то, чего канарейка делать НЕ должна. Механизм,
который по своей же неудаче объявляет выход врущим, выбрасывает живые
контакты пачками, и это ошибка дороже той, ради которой он заведён.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.canary import CANARY_MARK, CanaryWatch, canary_address  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ══════════════════════════ адрес канарейки ═════════════════════════════

def test_address_is_syntactically_legal():
    """Адрес обязан быть ЗАКОННЫМ, иначе проба ничего не значит.

    Сервер отверг бы кривой адрес по ФОРМЕ, а не по отсутствию получателя,
    и мы прочли бы этот отказ как «отвечает честно» — то есть канарейка
    выдавала бы врущему почтовику справку о честности.
    """
    from core.email_syntax import validate_email_syntax

    for домен in ("gmail.com", "corp-example.test", "почта.рф"):
        адрес = canary_address(домен)
        local, _, домен_из = адрес.rpartition("@")
        assert домен_из == домен
        assert len(local.encode("utf-8")) <= 64, "нарушен предел RFC 5321"
        assert re.match(r"^[a-z0-9-]+$", local), local
        assert validate_email_syntax(адрес) is True, (
            "адрес канарейки признан кривым: %s" % адрес)


def test_address_is_unique_every_time():
    """Повтор одного и того же адреса врущий сервер мог бы запомнить."""
    адреса = {canary_address("gmail.com") for _ in range(200)}
    assert len(адреса) == 200


def test_address_carries_a_human_readable_mark():
    """Метка нужна почтмейстеру на той стороне, а не программе.

    Увидев такой адрес в своём логе, он поймёт, что это проба существования,
    а не попытка доставки. Скрывать её незачем: врущий сервер отвечает 250
    всем подряд и в текст не смотрит.
    """
    assert CANARY_MARK in canary_address("corp.test")


# ══════════════════════════ когда пускать ═══════════════════════════════

def test_probe_only_after_a_valid_appears():
    """Без единого Valid защищать нечего — сессию не тратим."""
    watch = CanaryWatch()
    assert watch.should_probe("1.2.3.4", "corp.test") is False


def test_probe_once_per_exit_and_domain():
    """Дважды на одной паре не тратимся.

    Если выход честен, повторная проба ничего не добавит, а лишняя сессия к
    чужому почтовику — лишний повод попасться ему на глаза.
    """
    watch = CanaryWatch()
    watch.note_valid("1.2.3.4", "corp.test")
    assert watch.should_probe("1.2.3.4", "corp.test") is True
    watch.record("1.2.3.4", "corp.test", "invalid")
    watch.note_valid("1.2.3.4", "corp.test")
    assert watch.should_probe("1.2.3.4", "corp.test") is False


def test_probe_is_per_exit_not_per_domain():
    """Другой выход на том же домене проверяется отдельно.

    Врёт не домен, а пара «выход + домен»: один прокси под подозрением, а
    второй с тем же почтовиком работает честно.
    """
    watch = CanaryWatch()
    watch.note_valid("1.1.1.1", "corp.test")
    watch.record("1.1.1.1", "corp.test", "invalid")
    watch.note_valid("2.2.2.2", "corp.test")
    assert watch.should_probe("2.2.2.2", "corp.test") is True


# ══════════════════════════ что считается уликой ════════════════════════

def test_valid_canary_convicts_the_exit():
    """250 на заведомо мёртвый адрес — улика."""
    watch = CanaryWatch()
    watch.note_valid("1.2.3.4", "corp.test")
    assert watch.record("1.2.3.4", "corp.test", "valid") is True
    assert watch.is_compromised("1.2.3.4", "corp.test") is True
    assert watch.compromised_domains() == ["corp.test"]


def test_catchall_canary_convicts_too():
    """Домен, принявший и канарейку, и контрольный адрес, — тот же случай."""
    watch = CanaryWatch()
    watch.note_valid("1.2.3.4", "corp.test")
    assert watch.record("1.2.3.4", "corp.test", "catchall") is True


def test_control_a_refused_canary_is_not_evidence():
    """Отвергнутая канарейка — доказательство ЧЕСТНОСТИ, а не вины."""
    watch = CanaryWatch()
    watch.note_valid("1.2.3.4", "corp.test")
    assert watch.record("1.2.3.4", "corp.test", "invalid") is False
    assert watch.is_compromised("1.2.3.4", "corp.test") is False
    assert watch.compromised_domains() == []


def test_control_a_failed_probe_is_never_evidence():
    """Сорвавшаяся проба НИКОГО не обвиняет.

    Самая опасная ошибка этого механизма: объявить выход врущим по своему же
    таймауту и выбросить все его Valid. Живые контакты уехали бы пачками
    из-за нашего прокси.
    """
    for сбой in ("unknown", "greylisted", "risky", "", None, "timeout"):
        watch = CanaryWatch()
        watch.note_valid("1.2.3.4", "corp.test")
        assert watch.record("1.2.3.4", "corp.test", сбой) is False, сбой
        assert watch.compromised_domains() == [], сбой


def test_control_other_exits_stay_clean():
    """Уличённый выход не пачкает соседей.

    Иначе один плохой прокси обнулял бы работу всего пула.
    """
    watch = CanaryWatch()
    watch.note_valid("1.1.1.1", "corp.test")
    watch.record("1.1.1.1", "corp.test", "valid")
    assert watch.is_compromised("2.2.2.2", "corp.test") is False


def test_control_other_domains_stay_clean():
    """Уличённый выход на одном домене не пачкает другие домены.

    Почтовики защищаются каждый по-своему: gmail может тарпитить наш адрес,
    пока corp.test отвечает честно.
    """
    watch = CanaryWatch()
    watch.note_valid("1.1.1.1", "gmail.com")
    watch.record("1.1.1.1", "gmail.com", "valid")
    assert watch.is_compromised("1.1.1.1", "corp.test") is False


def test_summary_counts_probes_and_catches():
    watch = CanaryWatch()
    for домен, ответ in (("a.test", "invalid"), ("b.test", "valid"),
                         ("c.test", "unknown")):
        watch.note_valid("1.2.3.4", домен)
        watch.record("1.2.3.4", домен, ответ)
    свод = watch.summary()
    assert свод["проб"] == 3
    assert свод["поймано"] == 1
    assert свод["домены"] == ["b.test"]


# ══════════════════════════ связка с конвейером ═════════════════════════

class _Сеть(object):
    """Сеть, которая отвечает на канарейку что скажут."""

    def __init__(self, ответ):
        self.ответ = ответ
        self.спрошено = []

    def exit_ip_of(self, proxy):
        return "9.9.9.9"

    def stealth_smtp_ping(self, email, mx, **kw):
        self.спрошено.append(email)
        return {"status": self.ответ, "reason": "тест"}


def _конвейер(сеть):
    from core.pipeline import ValidationPipeline

    pipe = ValidationPipeline(callbacks={
        "on_log": lambda text, kind="info": None,
        "on_result": lambda *a: None,
        "on_complete": lambda: None,
    })
    pipe.network = сеть
    pipe.canary = CanaryWatch()
    return pipe


def test_pipeline_flies_a_canary_after_a_valid():
    """Конвейер действительно пускает пробу и адресует её тому же домену."""
    сеть = _Сеть("invalid")
    pipe = _конвейер(сеть)
    pipe._fly_canary("ivan@corp.test",
                     {"proxy": "socks5://1.2.3.4:1080",
                      "mx_records": ["mx.corp.test"]})
    assert len(сеть.спрошено) == 1
    assert сеть.спрошено[0].endswith("@corp.test")
    assert CANARY_MARK in сеть.спрошено[0]


def test_pipeline_marks_the_exit_when_canary_lives():
    сеть = _Сеть("valid")
    pipe = _конвейер(сеть)
    assert pipe._fly_canary("ivan@corp.test",
                            {"proxy": "socks5://1.2.3.4:1080",
                             "mx_records": ["mx.corp.test"]}) is True
    assert pipe.canary.compromised_domains() == ["corp.test"]


def test_control_pipeline_stays_silent_when_the_probe_throws():
    """Исключение в пробе никого не обвиняет и не роняет прогон."""

    class _Падучая(_Сеть):
        def stealth_smtp_ping(self, email, mx, **kw):
            raise RuntimeError("прокси умер")

    pipe = _конвейер(_Падучая("valid"))
    assert pipe._fly_canary("ivan@corp.test",
                            {"proxy": "p", "mx_records": ["mx"]}) is False
    assert pipe.canary.compromised_domains() == []


def test_control_pipeline_skips_when_no_mx_known():
    """Без MX спрашивать некуда — молча пропускаем."""
    сеть = _Сеть("valid")
    pipe = _конвейер(сеть)
    assert pipe._fly_canary("ivan@corp.test", {"proxy": "p"}) is False
    assert сеть.спрошено == []


def test_control_pipeline_survives_without_network():
    """Без сети (прогон только по кэшу) канарейка молчит."""
    pipe = _конвейер(_Сеть("valid"))
    pipe.network = None
    assert pipe._fly_canary("ivan@corp.test",
                            {"proxy": "p", "mx_records": ["mx"]}) is False


def test_revision_is_wired_at_the_end_of_the_run():
    """Уличённые домены пересматриваются и вычищаются из кэша.

    Без этого канарейка была бы строкой в логе, а владелец экспортирует
    данные, а не лог.
    """
    import io as _io
    источник = _io.open(os.path.join(ROOT, "core", "pipeline.py"),
                        encoding="utf-8").read()
    assert "self.canary.compromised_domains()" in источник
    хвост = источник[источник.index("compromised_domains()"):]
    assert "_revise(подставные" in хвост, "строки не пересматриваются"
    assert '_forget_cached(подставные' in хвост, "кэш не чистится"


def test_control_canary_state_is_not_persisted():
    """Состояние канареек НЕ переживает прогон.

    Врущим выход становится не навсегда: почтовик отпускает подозрение сам.
    Запомнив это на сутки, мы повторили бы дефект Б4, где тарпитинг оседал в
    долгой памяти и хоронил всю почту gmail на месяц.
    """
    import io as _io
    источник = _io.open(os.path.join(ROOT, "core", "canary.py"),
                        encoding="utf-8").read()
    for запретное in ("longterm", "sqlite", "json.dump", "open("):
        assert запретное not in источник, (
            "канарейки пишут состояние на диск: %s" % запретное)
