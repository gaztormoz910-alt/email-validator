# -*- coding: utf-8 -*-
import inspect
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def читать(*куски):
    return io.open(os.path.join(ROOT, *куски), encoding="utf-8").read()


def test_second_opinion_is_not_a_switch_in_the_window_any_more():
    разметка = читать("ui", "web", "index.html")
    скрипт = читать("ui", "web", "app.js")
    мост = читать("ui", "webapp.py")

    assert 'id="optConfirm"' not in разметка, (
        "тумблер вернулся в окно — значит его снова можно забыть включить")
    assert "optConfirm" not in скрипт, "окно снова читает убранный тумблер"
    assert 'payload.get("confirm"' not in мост, (
        "мост снова принимает настройку из окна и может её выключить")


def test_second_opinion_is_a_real_pipeline_parameter():
    from core.pipeline import ValidationPipeline

    параметры = inspect.signature(ValidationPipeline.start).parameters
    assert "confirm_valid" in параметры, "конвейер не принимает настройку"
    assert параметры["confirm_valid"].default is True, (
        "второе мнение выключено по умолчанию, а владелец включил его "
        "насовсем: цена лишней сессии несравнима с ценой рассылки в пустоту")
    assert "self.confirm_valid" in читать("core", "pipeline.py"), (
        "параметр принят, но никуда не положен")


def test_second_opinion_command_line_flag_is_actually_wired():
    cli = читать("cli.py")
    assert "--no-confirm-valid" in cli, "нет флага командной строки"
    assert "pipeline.confirm_valid =" in cli, (
        "флаг объявлен, но ни к чему не подключён — он ничего не делает")


def test_control_second_opinion_default_is_on_end_to_end():
    from core.pipeline import ValidationPipeline

    pipe = ValidationPipeline(callbacks={
        "on_log": lambda text, kind="info": None,
        "on_result": lambda *a: None,
        "on_complete": lambda: None,
    })
    поток = pipe.start(email_sources=[], threads=1, timeout=1, fix_typos=True,
                       check_spam=True, deep_ping=True, proxies=None)
    pipe.stop()
    поток.join(120)
    assert not поток.is_alive(), "рабочий поток конвейера не закончил подготовку за 120 с"
    assert getattr(pipe, "confirm_valid", False) is True, (
        "второе мнение не доехало до конвейера — подпись поменяли, а поведение нет")


def _прогнать(аргументы):
    import cli as модуль

    поток = io.StringIO()
    прежний = sys.stdout
    sys.stdout = поток
    try:
        код = модуль.main(аргументы)
    finally:
        sys.stdout = прежний
    return код, поток.getvalue()


def _отчёт(текст):
    путь = os.path.join(tempfile.mkdtemp(), "bounce.txt")
    io.open(путь, "w", encoding="utf-8").write(текст)
    return путь


ОТЧЁТ = (
    "To: a@dead.test\n"
    "550 5.1.1 <b@dead.test> no such user\n"
    "452 4.2.2 <alive@corp.test> mailbox full\n"
    "550 5.1.1 <c@dead.test> no such user\n"
)


def test_bounce_report_is_loadable_from_the_command_line():
    код, вывод = _прогнать(["bounces", _отчёт(ОТЧЁТ), "--dry-run"])
    assert код == 0, вывод
    assert "b@dead.test" in вывод
    assert "ничего не записано" in вывод.lower(), (
        "пробный прогон не сказал, что он пробный")


def test_bounce_hard_only_filter_separates_soft_bounces():
    код, вывод = _прогнать(["bounces", _отчёт(ОТЧЁТ),
                            "--hard-only", "5.1.1", "--dry-run"])
    assert код == 0, вывод
    assert "b@dead.test" in вывод and "c@dead.test" in вывод
    assert "alive@corp.test" not in вывод, (
        "мягкий отскок попал бы в Invalid — это выброшенный живой контакт")


def test_bounce_without_a_filter_takes_only_proven_hard_bounces():
    код, вывод = _прогнать(["bounces", _отчёт(ОТЧЁТ), "--dry-run"])
    assert код == 0, вывод
    assert "b@dead.test" in вывод and "c@dead.test" in вывод
    assert "alive@corp.test" not in вывод, (
        "мягкий отскок попал бы в Invalid — это выброшенный живой контакт")
    assert "a@dead.test" not in вывод, "строка без кода ответа — не доказательство"

    _код, вывод = _прогнать(["bounces", _отчёт(ОТЧЁТ)])
    assert "мягким или неясным" in вывод, "пропуск мягкого отскока не назван"
    assert "--hard-only" in вывод, "не сказано, как взять строки без кода"


def test_bounce_empty_report_says_so_and_fails():
    код, вывод = _прогнать(["bounces", _отчёт("совсем без адресов\n")])
    assert код == 1
    assert "не нашлось" in вывод


def test_bounce_reports_suspicious_domains():
    много = "".join("550 5.1.1 <u%d@catchy.test> no such user\n" % i
                    for i in range(4))
    _код, вывод = _прогнать(["bounces", _отчёт(много), "--hard-only", "5.1.1"])
    assert "catchy.test" in вывод
    assert "catch-all" in вывод


ВНУТРЕННИЕ = {
    "email_sources": "источники задаются загрузкой файла, а не переключателем",
    "proxies": "то же самое: список прокси загружается файлом",
    "self": "не настройка",
    "kwargs": "не настройка",
    "args": "не настройка",
}


def test_every_switch_is_reachable_from_some_surface():
    from core.pipeline import ValidationPipeline

    поверхности = читать("ui", "webapp.py") + читать("cli.py")
    недоступные = []
    for имя, параметр in inspect.signature(
            ValidationPipeline.start).parameters.items():
        if имя in ВНУТРЕННИЕ:
            continue
        if параметр.kind in (параметр.VAR_POSITIONAL, параметр.VAR_KEYWORD):
            continue
        if имя not in поверхности:
            недоступные.append(имя)
    assert not недоступные, (
        "настройки есть в движке, но включить их нечем: %s" % недоступные)


def test_every_switch_control_the_sweep_actually_sees_settings():
    from core.pipeline import ValidationPipeline

    имена = set(inspect.signature(ValidationPipeline.start).parameters)
    assert len(имена) >= 8, "обход нашёл всего %d параметров" % len(имена)
    for обязательная in ("threads", "timeout", "enable_ai", "confirm_valid"):
        assert обязательная in имена, обязательная


def test_every_switch_control_a_hidden_setting_would_be_caught():
    поверхности = читать("ui", "webapp.py") + читать("cli.py")
    выдуманная = "совершенно_секретная_настройка_которой_нет"
    assert выдуманная not in поверхности
    недоступные = [имя for имя in ("threads", выдуманная)
                   if имя not in поверхности]
    assert недоступные == [выдуманная], (
        "сито не отличает доступную настройку от скрытой: %s" % недоступные)
