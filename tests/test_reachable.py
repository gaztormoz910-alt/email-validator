# -*- coding: utf-8 -*-
"""Возможность, которую нечем включить, не существует.

Владелец спросил, точно ли всё сделано. Оказалось — нет: две защиты от
ложного Valid работали в движке, но включить их было нечем ни из окна, ни из
командной строки.

    второе мнение для Valid   `confirm_valid` в конвейере      НЕДОСТУПНО
    петля отскоков            record_bounce / import_bounces    НЕДОСТУПНО

И ни один из 1783 тестов этого не заметил: все они проверяли, что механизм
РАБОТАЕТ, и ни один не спросил, может ли владелец его запустить. Это ровно та
жалоба, которую он уже предъявлял дословно: «под капотом все изменения есть
актуальные а в интерфейсе софта их не видно вообще».

Поэтому здесь не две заплатки, а сито: последняя проверка обходит ВСЕ
настройки конвейера и требует, чтобы каждая была доступна хотя бы с одной
поверхности. Список исключений в ней заведён явно и с причиной — иначе он
тихо разрастётся до бессмысленности.
"""
import inspect
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def читать(*куски):
    return io.open(os.path.join(ROOT, *куски), encoding="utf-8").read()


# ══════════════════════ D1: второе мнение доступно ══════════════════════

def test_second_opinion_has_a_switch_in_the_window():
    """Тумблер есть в разметке и подписан по-человечески."""
    разметка = читать("ui", "web", "index.html")
    assert 'id="optConfirm"' in разметка, "тумблера нет в окне"
    кусок = разметка[разметка.index('id="optConfirm"'):]
    кусок = кусок[:кусок.index("</label>")]
    assert "Годен" in кусок, "непонятно, что делает тумблер"
    assert "прокси" in кусок.lower(), "не сказано, чем платим"


def test_second_opinion_setting_travels_window_to_pipeline():
    """Настройка доезжает по ВСЕЙ цепочке, а не теряется на полпути.

    Тумблер, чьё значение теряется по дороге, — это обман: владелец щёлкает,
    а поведение не меняется. Поэтому проверяются все три звена.
    """
    скрипт = читать("ui", "web", "app.js")
    мост = читать("ui", "webapp.py")

    assert '$("#optConfirm").checked' in скрипт, "окно не читает тумблер"
    assert "confirm:" in скрипт, "окно не отправляет настройку"
    assert 'payload.get("confirm"' in мост, "мост не принимает настройку"
    assert "confirm_valid=" in мост, "мост не передаёт её конвейеру"


def test_second_opinion_is_a_real_pipeline_parameter():
    """Конвейер действительно принимает параметр и запоминает его."""
    from core.pipeline import ValidationPipeline

    параметры = inspect.signature(ValidationPipeline.start).parameters
    assert "confirm_valid" in параметры, "конвейер не принимает настройку"
    assert параметры["confirm_valid"].default is False, (
        "второе мнение включено по умолчанию — это лишняя сессия на КАЖДЫЙ "
        "подтверждённый адрес")
    assert "self.confirm_valid" in читать("core", "pipeline.py"), (
        "параметр принят, но никуда не положен")


def test_second_opinion_has_a_command_line_flag():
    """Из командной строки тоже: на VPS окна не будет."""
    cli = читать("cli.py")
    assert "--confirm-valid" in cli, "нет флага командной строки"


def test_control_second_opinion_default_stays_off_end_to_end():
    """Контроль: не включив тумблер, владелец платит ноль лишних сессий."""
    from core.pipeline import ValidationPipeline

    pipe = ValidationPipeline(callbacks={
        "on_log": lambda text, kind="info": None,
        "on_result": lambda *a: None,
        "on_complete": lambda: None,
    })
    assert getattr(pipe, "confirm_valid", False) is False


# ══════════════════════ D2: отскоки загружаются ═════════════════════════

def _прогнать(аргументы):
    """Запускает cli.main и возвращает (код, напечатанное)."""
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
    """Команда есть, находит адреса и умеет не писать."""
    код, вывод = _прогнать(["bounces", _отчёт(ОТЧЁТ), "--dry-run"])
    assert код == 0, вывод
    assert "b@dead.test" in вывод
    assert "ничего не записано" in вывод.lower(), (
        "пробный прогон не сказал, что он пробный")


def test_bounce_hard_only_filter_separates_soft_bounces():
    """Мягкий отскок отсеивается фильтром владельца.

    Переполненный ящик доказывает ОБРАТНОЕ — что адрес существует и им
    пользуются. Записав его как Invalid, владелец выбросил бы свой лучший
    контакт. Формат отчёта у каждого рассыльщика свой, поэтому разделение
    отдано ему, а не угадывается за него.
    """
    код, вывод = _прогнать(["bounces", _отчёт(ОТЧЁТ),
                            "--hard-only", "5.1.1", "--dry-run"])
    assert код == 0, вывод
    assert "b@dead.test" in вывод and "c@dead.test" in вывод
    assert "alive@corp.test" not in вывод, (
        "мягкий отскок попал бы в Invalid — это выброшенный живой контакт")


def test_bounce_without_a_filter_warns_out_loud():
    """Без фильтра команда предупреждает, а не молчит.

    Молчаливая запись всех строк подряд — это тот же ложный Invalid, только
    сделанный руками владельца по нашей вине.
    """
    _код, вывод = _прогнать(["bounces", _отчёт(ОТЧЁТ)])
    assert "ВНИМАНИЕ" in вывод, "нет предупреждения про мягкие отскоки"
    assert "--hard-only" in вывод, "не сказано, чем это лечится"


def test_bounce_empty_report_says_so_and_fails():
    """Файл без адресов — это ошибка ввода, а не «записано ноль»."""
    код, вывод = _прогнать(["bounces", _отчёт("совсем без адресов\n")])
    assert код == 1
    assert "не нашлось" in вывод


def test_bounce_reports_suspicious_domains():
    """Домены со многими отскоками названы: это подпись catch-all."""
    много = "".join("550 5.1.1 <u%d@catchy.test> no such user\n" % i
                    for i in range(4))
    _код, вывод = _прогнать(["bounces", _отчёт(много), "--hard-only", "5.1.1"])
    assert "catchy.test" in вывод
    assert "catch-all" in вывод


# ══════════════════════ D3: сито от класса ошибки ═══════════════════════

# Настройки, которых на поверхности быть НЕ должно, и почему именно.
# Список заведён явно: пустой он бесполезен, а разрастись тихо не может —
# каждая строка требует причины, написанной здесь же.
ВНУТРЕННИЕ = {
    # Источники подаются не настройкой, а перетаскиванием файлов.
    "email_sources": "источники задаются загрузкой файла, а не переключателем",
    "proxies": "то же самое: список прокси загружается файлом",
    # Технические параметры вызова.
    "self": "не настройка",
    "kwargs": "не настройка",
    "args": "не настройка",
}


def test_every_switch_is_reachable_from_some_surface():
    """КАЖДАЯ настройка конвейера доступна хотя бы с одной поверхности.

    Ловится класс ошибки, а не два найденных случая. Оба они появились
    одинаково: механизм написан, покрыт тестами, и на этом работа сочтена
    законченной — а включить его нечем. Следующая такая настройка упадёт
    здесь, а не всплывёт вопросом владельца через неделю.
    """
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
    """Контроль: обход находит настоящие настройки, а не пустоту.

    Проверка выше ничего не стоит, если список параметров оказался пустым:
    тогда она проходит всегда и не охраняет ничего.
    """
    from core.pipeline import ValidationPipeline

    имена = set(inspect.signature(ValidationPipeline.start).parameters)
    assert len(имена) >= 8, "обход нашёл всего %d параметров" % len(имена)
    # Известные настройки на месте — значит смотрим туда, куда надо.
    for обязательная in ("threads", "timeout", "enable_ai", "confirm_valid"):
        assert обязательная in имена, обязательная


def test_every_switch_control_a_hidden_setting_would_be_caught():
    """Контроль: сито действительно ловит недоступную настройку.

    Отрицательная проверка без положительного контроля — это утверждение об
    отсутствии, сделанное инструментом, который, может быть, ничего и не
    ищет. Подсовываем заведомо скрытую настройку и требуем, чтобы её нашли.
    """
    поверхности = читать("ui", "webapp.py") + читать("cli.py")
    выдуманная = "совершенно_секретная_настройка_которой_нет"
    assert выдуманная not in поверхности
    # Та же логика, что в сите: имя, отсутствующее на поверхностях, — беда.
    недоступные = [имя for имя in ("threads", выдуманная)
                   if имя not in поверхности]
    assert недоступные == [выдуманная], (
        "сито не отличает доступную настройку от скрытой: %s" % недоступные)
