# -*- coding: utf-8 -*-
import io
import os
import sys
import unittest
import urllib.error
from contextlib import redirect_stdout
from unittest import mock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools import hide_old_releases as hide

РЕПО = "owner/repo"


class ПоддельныйGitHub:

    def __init__(self, теги, черновики=(), предварительные=(), появится_с_попытки=1,
                 не_слушается=False):
        self.релизы = [{"id": 100 + i, "tag_name": т, "draft": т in черновики,
                        "prerelease": т in предварительные} for i, т in enumerate(теги)]
        self.появится_с_попытки = появится_с_попытки
        self.не_слушается = не_слушается
        self.списков = 0
        self.правки = []
        self.токены = set()

    def __call__(self, метод, путь, токен=None, тело=None):
        self.токены.add(токен)
        if метод == "GET" and путь.startswith("/repos/%s/releases?" % РЕПО):
            страница = int(путь.rsplit("page=", 1)[1])
            if страница == 1:
                self.списков += 1
            видимые = self.релизы if self.списков >= self.появится_с_попытки else self.релизы[1:]
            return видимые[(страница - 1) * 100:страница * 100]
        if метод == "GET" and путь == "/repos/%s/releases/latest" % РЕПО:
            for р in self.релизы:
                if not р["draft"] and not р["prerelease"]:
                    return р
            return None
        if метод == "PATCH":
            номер = int(путь.rsplit("/", 1)[1])
            self.правки.append((номер, тело))
            if not self.не_слушается:
                for р in self.релизы:
                    if р["id"] == номер:
                        р["draft"] = тело["draft"]
            return {}
        raise AssertionError("неожиданный запрос %s %s" % (метод, путь))


def выполнить(api, оставить="v1.3.7", применить=True, токен="t", сон=None):
    вывод = io.StringIO()
    сны = [] if сон is None else сон
    with redirect_stdout(вывод):
        код = hide.выполнить(РЕПО, оставить, применить, токен, получить=api, спать=сны.append)
    return код, вывод.getvalue()


class TestПлан(unittest.TestCase):

    def test_прячется_всё_опубликованное_кроме_нового(self):
        api = ПоддельныйGitHub(["v1.3.7", "v1.3.6", "v1.3.5"], черновики={"v1.3.5"},
                               предварительные={"v1.3.6"})
        план = hide.план(api.релизы, "v1.3.7")
        self.assertEqual([р["tag_name"] for р in план], ["v1.3.6"])

    def test_новее_оставляемого_не_прячем(self):
        for черновики in ((), {"v1.3.7"}):
            with self.subTest(черновики=черновики):
                api = ПоддельныйGitHub(["v1.3.7", "v1.3.6", "v1.3.5"], черновики=черновики)
                with self.assertRaises(hide.Отказ):
                    hide.план(api.релизы, "v1.3.6")

    def test_ненастоящий_номер_отказ(self):
        api = ПоддельныйGitHub(["test", "v1.3.6"])
        with self.assertRaises(hide.Отказ):
            hide.план(api.релизы, "test")

    def test_версии_сравниваются_числами_а_не_строками(self):
        api = ПоддельныйGitHub(["v1.10.0", "v1.9.0"])
        self.assertEqual([р["tag_name"] for р in hide.план(api.релизы, "v1.10.0")], ["v1.9.0"])
        with self.assertRaises(hide.Отказ):
            hide.план(api.релизы, "v1.9.0")

    def test_новый_не_опубликован_значит_отказ(self):
        for теги, черновики in ((["v1.3.6"], ()), (["v1.3.7", "v1.3.6"], {"v1.3.7"})):
            with self.subTest(теги=теги, черновики=черновики):
                api = ПоддельныйGitHub(теги, черновики=черновики)
                with self.assertRaises(hide.Отказ):
                    hide.план(api.релизы, "v1.3.7")


class TestВыполнение(unittest.TestCase):

    def test_план_без_apply_ничего_не_меняет(self):
        api = ПоддельныйGitHub(["v1.3.7", "v1.3.6"])
        код, вывод = выполнить(api, применить=False, токен=None)
        self.assertEqual(код, 0)
        self.assertEqual(api.правки, [])
        self.assertIn("v1.3.6", вывод)

    def test_прячет_старые_и_проверяет_итог(self):
        api = ПоддельныйGitHub(["v1.3.7", "v1.3.6", "v1.3.5", "v1.0.0"])
        код, вывод = выполнить(api)
        self.assertEqual(код, 0)
        self.assertEqual(sorted(номер for номер, _ in api.правки), [101, 102, 103])
        self.assertTrue(all(тело == {"draft": True} for _, тело in api.правки))
        self.assertEqual([р["tag_name"] for р in api.релизы if not р["draft"]], ["v1.3.7"])
        self.assertEqual(api.токены, {"t"})
        self.assertIn("HIDE_OLD_RELEASES_OK", вывод)

    def test_новый_виден_не_сразу_ждём_и_не_трогаем_раньше(self):
        api = ПоддельныйGitHub(["v1.3.7", "v1.3.6"], появится_с_попытки=3)
        сны = []
        код, _ = выполнить(api, сон=сны)
        self.assertEqual(код, 0)
        self.assertEqual(len(сны), 2)
        self.assertEqual([р["tag_name"] for р in api.релизы if not р["draft"]], ["v1.3.7"])

    def test_новый_так_и_не_появился_ничего_не_тронуто(self):
        api = ПоддельныйGitHub(["v1.3.7", "v1.3.6", "v1.3.5"], появится_с_попытки=99)
        with self.assertRaises(hide.Отказ):
            выполнить(api)
        self.assertEqual(api.правки, [], "при невидимом новом релизе спрятано хоть что-то")

    def test_github_не_послушался_значит_провал(self):
        api = ПоддельныйGitHub(["v1.3.7", "v1.3.6"], не_слушается=True)
        with self.assertRaises(hide.Отказ):
            выполнить(api)

    def test_apply_без_токена_ничего_не_трогает(self):
        api = ПоддельныйGitHub(["v1.3.7", "v1.3.6"])
        with self.assertRaises(hide.Отказ):
            выполнить(api, токен=None)
        self.assertEqual(api.правки, [])

    def test_больше_ста_релизов_читаются_все_страницы(self):
        теги = ["v1.3.7"] + ["v0.%d" % i for i in range(150)]
        api = ПоддельныйGitHub(теги)
        код, _ = выполнить(api)
        self.assertEqual(код, 0)
        self.assertEqual(len(api.правки), 150)

    def test_main_без_keep_не_работает(self):
        with mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
            hide.main([])

    def test_main_сбой_сети_даёт_ненулевой_код(self):
        сбой = mock.Mock(side_effect=urllib.error.URLError("нет сети"))
        with mock.patch.object(hide, "запрос", сбой), redirect_stdout(io.StringIO()) as вывод, \
                mock.patch.dict(os.environ, {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": РЕПО}):
            код = hide.main(["--keep", "v1.3.7", "--apply"])
        self.assertEqual(код, 1)
        self.assertIn("ОТКАЗ", вывод.getvalue())


def _ответ(сырое):
    ответ = mock.MagicMock()
    ответ.__enter__.return_value.read.return_value = сырое
    return ответ


def _http(код):
    return urllib.error.HTTPError("https://api.github.com/x", код, "сбой", {}, None)


class TestПовторЗапроса(unittest.TestCase):

    def _запрос(self, *ответы):
        сны = []
        with mock.patch.object(hide.urllib.request, "urlopen", side_effect=list(ответы)) as открыть, \
                redirect_stdout(io.StringIO()):
            итог = hide.запрос("GET", "/repos/%s/releases?page=1" % РЕПО, спать=сны.append)
        return итог, открыть.call_count, сны

    def test_504_повторяется_и_проходит(self):
        итог, вызовов, сны = self._запрос(_http(504), _ответ(b'[{"tag_name": "v1.3.7"}]'))
        self.assertEqual(итог, [{"tag_name": "v1.3.7"}])
        self.assertEqual(вызовов, 2)
        self.assertEqual(сны, [hide.ПАУЗА_ЗАПРОСА_С])

    def test_обрыв_сети_повторяется(self):
        итог, вызовов, _ = self._запрос(urllib.error.URLError("connection reset"), _ответ(b"[]"))
        self.assertEqual((итог, вызовов), ([], 2))

    def test_404_не_повторяется(self):
        with self.assertRaises(urllib.error.HTTPError):
            self._запрос(_http(404), _ответ(b"[]"))

    def test_после_всех_попыток_сбой_выходит_наружу(self):
        сбои = [_http(503) for _ in range(hide.ПОПЫТОК_ЗАПРОСА)]
        сны = []
        with mock.patch.object(hide.urllib.request, "urlopen", side_effect=сбои) as открыть, \
                redirect_stdout(io.StringIO()), self.assertRaises(urllib.error.HTTPError):
            hide.запрос("GET", "/x", спать=сны.append)
        self.assertEqual(открыть.call_count, hide.ПОПЫТОК_ЗАПРОСА)
        self.assertEqual(len(сны), hide.ПОПЫТОК_ЗАПРОСА - 1)


class GitHubСОтстающимLatest(ПоддельныйGitHub):

    def __init__(self, теги, отстаёт, **kw):
        ПоддельныйGitHub.__init__(self, теги, **kw)
        self.отстаёт = отстаёт
        self.latest_вызовов = 0

    def __call__(self, метод, путь, токен=None, тело=None):
        if метод == "GET" and путь == "/repos/%s/releases/latest" % РЕПО:
            self.latest_вызовов += 1
            if self.latest_вызовов <= self.отстаёт:
                return self.релизы[1]
        return ПоддельныйGitHub.__call__(self, метод, путь, токен, тело)


class TestСверкаСПаузой(unittest.TestCase):

    def test_запаздывающий_latest_не_роняет_шаг(self):
        api = GitHubСОтстающимLatest(["v1.3.7", "v1.3.6"], отстаёт=2)
        сны = []
        код, вывод = выполнить(api, сон=сны)
        self.assertEqual(код, 0)
        self.assertIn("HIDE_OLD_RELEASES_OK", вывод)
        self.assertEqual(сны, [hide.ПАУЗА_С, hide.ПАУЗА_С])

    def test_так_и_не_обновился_значит_провал(self):
        api = GitHubСОтстающимLatest(["v1.3.7", "v1.3.6"], отстаёт=99)
        сны = []
        with self.assertRaises(hide.Отказ):
            выполнить(api, сон=сны)
        self.assertEqual(len(сны), hide.ПОПЫТОК_СВЕРКИ - 1)


if __name__ == "__main__":
    unittest.main()
