# -*- coding: utf-8 -*-
"""Второе мнение для Valid, петля отскоков, колонки выгрузки, подмена домена.

Четыре требования владельца одним заходом. Общее у них одно: каждое закрывает
путь, по которому «Годен» доезжал до выгрузки без доказательства.

Отдельно про последнее. Владелец спросил прямо: «ты при проверке меняешь
домен на другой, проверяешь почту с изменённым доменом и говоришь, что она
валидная?». Ответ был «да, так было» — дефект Б1. Проверка здесь сквозная, от
загруженной строки до выданной: смотреть на одну функцию мало, потому что
подменить домен умеют три разных места.
"""
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.cache import ResultCache                       # noqa: E402
from core.cleaner import EmailCleaner                    # noqa: E402
from core.streamer import StreamLoader                   # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _tmp_cache():
    return ResultCache(path=os.path.join(tempfile.mkdtemp(), "r2.sqlite"))


# ══════════════════════ второе мнение для Valid ═════════════════════════

class _Сеть(object):
    """Сеть, у которой второй выход отвечает что скажут."""

    def __init__(self, второй):
        self.второй = второй
        self.спрошено = []
        self.proxies = ["socks5://1.1.1.1:1080", "socks5://2.2.2.2:1080"]

    def confirm_valid_from_other_exit(self, email, mx, first_proxy=None):
        self.спрошено.append((email, first_proxy))
        return self.второй


def _конвейер(сеть=None):
    from core.pipeline import ValidationPipeline

    pipe = ValidationPipeline(callbacks={
        "on_log": lambda text, kind="info": None,
        "on_result": lambda *a: None,
        "on_complete": lambda: None,
    })
    pipe.network = сеть
    return pipe


def test_second_opinion_asks_a_different_exit():
    """Спрашивается тот же адрес, но с другого выхода."""
    сеть = _Сеть(True)
    pipe = _конвейер(сеть)
    итог = pipe._second_opinion_on_valid(
        "ivan@corp.test", {"proxy": "socks5://1.1.1.1:1080",
                           "mx_records": ["mx.corp.test"]})
    assert итог is True
    assert сеть.спрошено == [("ivan@corp.test", "socks5://1.1.1.1:1080")]


def test_second_opinion_disagreement_lowers_the_verdict():
    """Расхождение двух выходов понижает статус до Unknown, а не до Invalid.

    Отвергнуть могли по репутации второго прокси, а не по отсутствию ящика.
    Два выхода разошлись — значит доказательства нет ни у одной стороны.
    """
    источник = io.open(os.path.join(ROOT, "core", "pipeline.py"),
                       encoding="utf-8").read()
    кусок = источник[источник.index("_second_opinion_on_valid(email, res)"):]
    кусок = кусок[:600]
    assert 'raw_status = "unknown"' in кусок, "статус не понижается"
    assert "Invalid" not in кусок.split("status_display")[1][:120], (
        "расхождение выходов превращается в приговор — это ложный Invalid")


def test_control_second_opinion_is_off_by_default():
    """По умолчанию выключено: это лишняя сессия на КАЖДЫЙ Valid.

    Включается перед тем прогоном, после которого владелец рассылает.
    """
    pipe = _конвейер(_Сеть(True))
    assert getattr(pipe, "confirm_valid", False) is False


def test_control_second_opinion_failure_keeps_the_first_answer():
    """None — «сверить не удалось», и первый ответ остаётся в силе.

    Иначе наш собственный сбой понижал бы честно подтверждённые адреса.
    """
    pipe = _конвейер(_Сеть(None))
    assert pipe._second_opinion_on_valid(
        "a@corp.test", {"proxy": "p", "mx_records": ["mx"]}) is None


def test_control_second_opinion_survives_a_throwing_network():
    class _Падучая(_Сеть):
        def confirm_valid_from_other_exit(self, *a, **kw):
            raise RuntimeError("прокси умер")

    pipe = _конвейер(_Падучая(True))
    assert pipe._second_opinion_on_valid(
        "a@corp.test", {"proxy": "p", "mx_records": ["mx"]}) is None


def test_control_second_opinion_needs_a_second_exit():
    """Без второго выходного адреса второго мнения не существует.

    Возвращается None — «сверить не с чем», а не молчаливое согласие.
    """
    from core.network import NetworkValidator

    nv = NetworkValidator(proxies=[])          # прямое соединение: выход один
    nv._mx_delay = lambda mx: 0.0
    assert nv.confirm_valid_from_other_exit(
        "a@corp.test", ["mx.corp.test"], first_proxy=None) is None


# ══════════════════════ петля отскоков ══════════════════════════════════

def test_bounce_overrides_a_cached_valid():
    """Отскок перекрывает даже свежий «Годен».

    Проба RCPT спрашивает сервер о НАМЕРЕНИИ; отскок означает, что письмо
    приняли, донесли до ящика и отвергли там. Между этими событиями вся
    внутренняя маршрутизация получателя, о которой снаружи не знает никто.
    """
    cache = _tmp_cache()
    try:
        cache.put("a@dead.test", "Valid", "250 OK", "mx", {})
        assert cache.get("a@dead.test")["status"] == "Valid"
        assert cache.record_bounce("a@dead.test", "550 5.1.1 no such user")
        запись = cache.get("a@dead.test")
        assert запись["status"] == "Invalid/Bounce"
        assert "тскок" in запись["reason"]
        assert "550 5.1.1" in запись["reason"], "подробность потеряна"
    finally:
        cache.close()


def test_bounce_import_counts_what_it_wrote():
    cache = _tmp_cache()
    try:
        assert cache.import_bounces(["a@x.test", "b@x.test", ""]) == 2
    finally:
        cache.close()


def test_bounce_heavy_domains_are_reported():
    """Домен со многими отскоками — кандидат в catch-all.

    Сервер принимал всех подряд, а на доставке выяснялось, что ящиков нет.
    Это та же подпись, что и «у домена все адреса ответили 250», только
    добытая настоящей рассылкой.
    """
    cache = _tmp_cache()
    try:
        for i in range(4):
            cache.record_bounce("u%d@catchy.test" % i)
        cache.record_bounce("one@honest.test")
        assert cache.bounced_domains(min_count=3) == ["catchy.test"]
    finally:
        cache.close()


def test_control_soft_bounce_is_not_this_function():
    """Контроль: в документации сказано, что мягкий отскок сюда не идёт.

    Переполненный ящик доказывает ОБРАТНОЕ — что адрес существует и им
    пользуются. Записав его как Invalid, мы выбросили бы лучший из контактов.
    """
    from core.cache import ResultCache as _RC

    док = _RC.record_bounce.__doc__ or ""
    assert "ЖЁСТКИЙ" in док
    assert "переполнен" in док.lower()


def test_control_bounce_does_not_touch_other_addresses():
    cache = _tmp_cache()
    try:
        cache.put("keep@x.test", "Valid", "250 OK", "mx", {})
        cache.record_bounce("drop@x.test")
        assert cache.get("keep@x.test")["status"] == "Valid"
    finally:
        cache.close()


# ══════════════════════ колонки выгрузки ════════════════════════════════

def _export_block():
    источник = io.open(os.path.join(ROOT, "ui", "webapp.py"),
                       encoding="utf-8").read()
    начало = источник.index('writer.writerow(["Email", "OriginalEmail"')
    return источник[начало:начало + 4000]


def test_export_has_the_new_columns():
    """Доля Valid по домену и признак «из кэша» есть в заголовке."""
    блок = _export_block()
    for колонка in ("DomainValidRatio", "DomainChecked", "FromCache"):
        assert '"%s"' % колонка in блок, "нет колонки %s" % колонка


def test_export_header_and_row_have_the_same_width():
    """У КАЖДОЙ выгрузки заголовок и строка совпадают по числу полей.

    Разъехавшись, они сдвинут все значения на колонку, и владелец будет
    читать имя в графе статуса — молчаливая порча всей выгрузки.

    Три поправки к первым версиям, и все три — про оракул, а не про код:

      * делил список по запятым верхнего уровня и насчитал лишнее поле:
        запятые нашлись в русских комментариях внутри списка;
      * брал последний найденный заголовок и сверял полный экспорт с
        сегментным — выгрузок в окне не одна;
      * пары «заголовок и ближайшая строка ниже» ошибались на третьей
        выгрузке (у парсера), где строки идут генератором, а не списком.

    Оракул, который ошибается сам, хуже отсутствующего: он обвиняет
    исправный код. Поэтому пара берётся по ФУНКЦИИ, в которой оба лежат.
    """
    import ast

    дерево = ast.parse(io.open(os.path.join(ROOT, "ui", "webapp.py"),
                               encoding="utf-8").read())

    def поля(узел):
        """(заголовки, строки) внутри одного тела функции."""
        заг, стр = [], []
        for вложенный in ast.walk(узел):
            if not (isinstance(вложенный, ast.Call)
                    and isinstance(вложенный.func, ast.Attribute)
                    and вложенный.func.attr == "writerow"
                    and вложенный.args):
                continue
            арг = вложенный.args[0]
            if isinstance(арг, ast.List) and арг.elts and all(
                    isinstance(э, ast.Constant) and isinstance(э.value, str)
                    for э in арг.elts):
                заг.append([э.value for э in арг.elts])
            elif (isinstance(арг, ast.Call) and isinstance(арг.func, ast.Name)
                  and арг.func.id == "csv_row" and арг.args
                  and isinstance(арг.args[0], ast.List)):
                стр.append(арг.args[0].elts)
        return заг, стр

    пары = []
    for узел in ast.walk(дерево):
        if not isinstance(узел, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        заг, стр = поля(узел)
        # Обе части в одной функции — значит это одна выгрузка целиком.
        if len(заг) == 1 and len(стр) == 1:
            пары.append((узел.name, заг[0], стр[0]))

    assert len(пары) >= 2, (
        "выгрузок с заголовком и строкой найдено %d, ожидалось не меньше двух"
        % len(пары))

    расхождения = ["%s: заголовок %d полей, данные %d"
                   % (имя, len(заг), len(стр))
                   for имя, заг, стр in пары if len(заг) != len(стр)]
    assert not расхождения, расхождения

    полная = [заг for _имя, заг, _стр in пары if "OriginalEmail" in заг]
    assert полная, "не найдена полная выгрузка"
    assert полная[0][-3:] == ["DomainValidRatio", "DomainChecked", "FromCache"]


def test_export_ratio_is_computed_in_the_pipeline():
    """Число действительно считается, а не осталось пустой колонкой."""
    источник = io.open(os.path.join(ROOT, "core", "pipeline.py"),
                       encoding="utf-8").read()
    assert 'data["domain_valid_ratio"]' in источник
    assert 'data["domain_checked"]' in источник


# ══════════════════════ подмена домена: сквозная проверка ═══════════════

# Домены законные. Владелец спросил именно про этот случай.
СКВОЗНЫЕ = [
    "user@sky.company.co.uk",
    "b@aol.company.com",
    "a@web.de.hosting.net",
    "d@list.ru-company.com",
    "John.Smith@Corp-Example.com",
    "k@bbc.company.co.uk",
]


def test_no_silent_swap_from_file_to_verdict():
    """От строки в файле до строки на выходе домен не меняется.

    Проверяется весь путь загрузки: `StreamLoader` (он приводил регистр) и
    `EmailCleaner` (он подменял домен по префиксу). Смотреть на одну функцию
    мало — подменить домен умели оба.
    """
    содержимое = "\n".join(СКВОЗНЫЕ) + "\n"
    загружено = [e for e, _ in StreamLoader(
        [{"type": "text", "content": содержимое}]).stream_emails()]
    cleaner = EmailCleaner()

    подменено = []
    for исходный, после_загрузки in zip(СКВОЗНЫЕ, загружено):
        итог = cleaner.correct_and_normalize(после_загрузки)
        домен_был = исходный.rsplit("@", 1)[1].lower()
        домен_стал = (итог or "").rsplit("@", 1)[-1].lower()
        if домен_был != домен_стал:
            подменено.append("%s -> %s" % (исходный, итог))
    assert not подменено, "домен подменён на пути к проверке: %s" % подменено


def test_no_silent_swap_mailbox_name_survives_too():
    """Имя ящика тоже доходит нетронутым.

    Иначе проверялся бы другой ящик на правильном домене — та же ошибка,
    только менее заметная.
    """
    загружено = [e for e, _ in StreamLoader(
        [{"type": "text", "content": "John.Smith@Corp-Example.com\n"}]
    ).stream_emails()]
    итог = EmailCleaner().correct_and_normalize(загружено[0])
    assert итог.split("@")[0] == "John.Smith", итог


def test_no_silent_swap_typo_fix_is_only_a_suggestion():
    """Опечатка НЕ исправляется молча: это предложение, а не действие.

    `gmial.com` не превращается в `gmail.com` до проверки. Иначе вердикт
    выносился бы про чужой ящик — и «Годен» про постороннего человека, и
    «нет такого» про настоящий адрес, который никто не спрашивал.
    """
    cleaner = EmailCleaner()
    итог = cleaner.correct_and_normalize("ivan@gmial.com")
    assert итог == "ivan@gmial.com", "опечатка исправлена молча: %s" % итог
    # Предложение при этом есть — им пользуется конвейер, но только после
    # ответа DNS «такого домена нет».
    assert cleaner.suggest_domain_fix("ivan@gmial.com") == "ivan@gmail.com"


def test_no_silent_swap_original_is_carried_to_the_output():
    """Исходная строка едет до выдачи отдельным полем.

    Даже когда очистка что-то поправила по делу (склейка мусора), владелец
    обязан видеть, что именно он загружал.
    """
    источник = io.open(os.path.join(ROOT, "core", "pipeline.py"),
                       encoding="utf-8").read()
    assert "original_email" in источник
    выгрузка = io.open(os.path.join(ROOT, "ui", "webapp.py"),
                       encoding="utf-8").read()
    assert '"OriginalEmail"' in выгрузка


def test_no_silent_swap_control_real_glue_is_still_repaired():
    """Контроль: строка, которая доменом не является, по-прежнему чинится.

    Без него «исправление» свелось бы к отключению очистки, и живые адреса
    уехали бы в «мёртвый домен».
    """
    cleaner = EmailCleaner()
    assert cleaner.correct_and_normalize("u@gmail.comtelefoon") == "u@gmail.com"
    assert cleaner.correct_and_normalize("z@corp.com-jobs") == "z@corp.com"


# ══════════════════════ ведущая точка в имени ящика ═════════════════════

def test_leading_dot_is_rejected_for_ascii_and_non_ascii_alike():
    """Точка первой в имени ящика незаконна независимо от алфавита.

    Найдено набором с известным ответом: семь заведомо кривых форм из восьми
    отвергались, а `.ведущая-точка@corp.test` признавался законным. Причина —
    ветка для не-ASCII имени возвращала «годен» сразу после проверки длины, и
    ни одно правило про точки к таким адресам не применялось.

    SMTPUTF8 (RFC 6531) расширяет НАБОР ЗНАКОВ, а не грамматику: dot-atom из
    RFC 5322 §3.4.1 действует для UTF-8 так же.
    """
    from core.email_syntax import validate_email_syntax

    кривые = [".leading@corp.test", ".ведущая@corp.test",
              "хвост.@corp.test", "хвост.@corp.test",
              "две..точки@corp.test", "две..точки.ру@corp.test"]
    принятые = [a for a in кривые if validate_email_syntax(a)]
    assert not принятые, "приняты кривые формы: %s" % принятые


def test_control_legal_international_addresses_still_pass():
    """Контроль: законные международные адреса не задеты.

    Ровно ради них ветка для не-ASCII и была заведена: общая регулярка
    разбирает ASCII-atext, и `иван` в него не входит. Отбраковать их значило
    бы вернуть ложный invalid, из-за которого живой адрес хоронится без
    единого запроса в сеть.
    """
    from core.email_syntax import validate_email_syntax

    законные = ["иван@почта.рф", "müller@bücher.de", "иван.петров@mail.ru",
                "john.doe@gmail.com", "a-b_c+tag@corp.test"]
    отвергнутые = [a for a in законные if not validate_email_syntax(a)]
    assert not отвергнутые, "отвергнуты законные адреса: %s" % отвергнутые


def test_control_quoted_leading_dot_is_still_legal():
    """Контроль: в кавычках точка первой ЗАКОННА (RFC 5321 §4.1.2).

    Проверка ведущей точки идёт по всему адресу, и это верно ровно потому,
    что для формы в кавычках она не выполняется вовсе.
    """
    from core.email_syntax import validate_email_syntax

    assert validate_email_syntax('".leading"@corp.test') is True
    assert validate_email_syntax('"very.unusual"@example.com') is True

