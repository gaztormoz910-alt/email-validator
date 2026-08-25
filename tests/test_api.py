"""REST API: логика проверяется напрямую, а сеть — на живом сервере.

Обработчики отделены от HTTP (функция handle), поэтому большую часть можно
проверить без сокетов. Но одного этого мало: сервер может не подняться, не
отдать заголовки или пустить чужого. Поэтому в конце поднимается настоящий
ThreadingHTTPServer на свободном порту и опрашивается по-настоящему.
"""
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.server import handle, describe, build_server, MAX_EMAILS_PER_CALL


class TestHandlerLogic(unittest.TestCase):
    """Ответы обработчиков без поднятия сервера."""

    def test_health(self):
        code, body = handle("/api/health", {})
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])

    def test_validate_single_returns_full_picture(self):
        code, body = handle("/api/validate-single", {"email": "John.Doe@Gmail.com"})
        self.assertEqual(code, 200)
        self.assertEqual(body["email"], "john.doe@gmail.com")
        self.assertEqual(body["provider"], "Gmail")
        self.assertTrue(body["syntax_ok"])
        self.assertIn("status", body)
        self.assertIn("dedup_key", body)

    def test_validate_single_repairs_junk(self):
        """Тот самый адрес из файла владельца с обратной кавычкой."""
        _code, body = handle("/api/validate-single", {"email": "`hjohnuc@gmail.com"})
        self.assertEqual(body["email"], "hjohnuc@gmail.com")
        self.assertTrue(body["syntax_ok"])

    def test_validate_single_flags_short_gmail_as_risky(self):
        _code, body = handle("/api/validate-single", {"email": "ca@gmail.com"})
        self.assertEqual(body["status"], "risky",
                         "адрес, невозможный по правилам Gmail, отдан как годный")
        self.assertEqual(body["local_rule"], "unlikely")

    def test_validate_single_flags_disposable(self):
        _code, body = handle("/api/validate-single", {"email": "a@mailinator.com"})
        self.assertEqual(body["status"], "invalid")
        self.assertTrue(body["disposable"])

    def test_validate_single_flags_role(self):
        _code, body = handle("/api/validate-single", {"email": "info@corp-x.com"})
        self.assertEqual(body["status"], "risky")
        self.assertTrue(body["role_based"])

    def test_validate_single_requires_email(self):
        for payload in ({}, {"email": ""}, {"email": 123}, {"email": None}):
            with self.subTest(payload=payload):
                code, body = handle("/api/validate-single", payload)
                self.assertEqual(code, 400)
                self.assertIn("error", body)

    def test_validate_batch(self):
        code, body = handle("/api/validate-batch",
                            {"emails": ["a@gmail.com", "info@corp.com"]})
        self.assertEqual(code, 200)
        self.assertEqual(body["count"], 2)
        self.assertEqual(len(body["results"]), 2)

    def test_batch_size_is_capped(self):
        code, body = handle("/api/validate-batch",
                            {"emails": ["a@b.com"] * (MAX_EMAILS_PER_CALL + 1)})
        self.assertEqual(code, 400)
        self.assertIn("не больше", body["error"])

    def test_clean_dedupes_like_the_pipeline(self):
        # john.doe и johndoe — один ящик (Gmail игнорирует точки), а вот
        # john+tag адресует ящик john, и это ДРУГОЙ адрес. Итого три разных.
        code, body = handle("/api/clean", {"emails": [
            "John.Doe@gmail.com", "johndoe@gmail.com", "john+tag@gmail.com",
            "`hjohnuc@gmail.com", "мусор", ""]})
        self.assertEqual(code, 200)
        self.assertEqual(body["unique"], 3,
                         f"дедуп по API разошёлся с пайплайном: {body['emails']}")
        self.assertNotIn("мусор", body["emails"])

    def test_clean_matches_pipeline_on_owner_file(self):
        """Тот же файл владельца через API даёт те же 59 адресов."""
        import io as _io
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "data", "testdata", "test_1.txt")
        with _io.open(path, encoding="utf-8", errors="ignore") as handle_file:
            lines = [line.strip() for line in handle_file if line.strip()]
        _code, body = handle("/api/clean", {"emails": lines})
        self.assertEqual(body["unique"], 59,
                         "API и пайплайн расходятся на реальном файле")

    def test_base_operations(self):
        a = ["x@a.com", "y@a.com"]
        b = ["y@a.com", "z@a.com"]
        self.assertEqual(handle("/api/merge", {"a": a, "b": b})[1]["count"], 3)
        self.assertEqual(handle("/api/subtract", {"a": a, "b": b})[1]["emails"],
                         ["x@a.com"])
        self.assertEqual(handle("/api/intersect", {"a": a, "b": b})[1]["emails"],
                         ["y@a.com"])

    def test_unknown_path_is_404(self):
        code, body = handle("/api/nope", {})
        self.assertEqual(code, 404)
        self.assertIn("error", body)

    def test_bad_field_types_are_400_not_500(self):
        for payload in ({"emails": "не список"}, {"emails": 5}, {"a": 1, "b": 2}):
            with self.subTest(payload=payload):
                code, _body = handle("/api/clean", payload)
                self.assertIn(code, (200, 400),
                              "кривой ввод обрушил обработчик в 500")

    def test_describe_survives_garbage(self):
        for junk in ("", "   ", "@@@", "a" * 500):
            with self.subTest(junk=junk):
                result = describe(junk)
                self.assertIn("status", result)


class TestBindingSafety(unittest.TestCase):
    """Наружу без токена сервер не выпускается."""

    def test_external_bind_without_token_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            build_server(host="0.0.0.0", port=0, token="")
        self.assertIn("токен", str(caught.exception))

    def test_localhost_without_token_is_allowed(self):
        server = build_server(host="127.0.0.1", port=0, token="")
        try:
            self.assertTrue(server.server_address[1] > 0)
        finally:
            server.server_close()


class TestLiveServer(unittest.TestCase):
    """Настоящий сервер на свободном порту: заголовки, коды, авторизация."""

    @classmethod
    def setUpClass(cls):
        cls.token = "test-token-123"
        cls.server = build_server(host="127.0.0.1", port=0, token=cls.token)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _post(self, path, payload, token=None):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"})
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))

    def test_live_health_over_get(self):
        with urllib.request.urlopen(
                f"http://127.0.0.1:{self.port}/api/health", timeout=10) as response:
            self.assertEqual(response.status, 200)
            self.assertTrue(json.loads(response.read().decode("utf-8"))["ok"])

    def test_live_validate_single(self):
        status, body = self._post("/api/validate-single",
                                  {"email": "john.doe@gmail.com"}, self.token)
        self.assertEqual(status, 200)
        self.assertEqual(body["provider"], "Gmail")

    def test_live_requires_token(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self._post("/api/validate-single", {"email": "a@b.com"})
        self.assertEqual(caught.exception.code, 401,
                         "запрос без токена был обслужен")

    def test_live_rejects_broken_json(self):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/validate-single",
            data=b"{not json at all",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.token}"})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=10)
        self.assertEqual(caught.exception.code, 400)

    def test_live_returns_json_content_type(self):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/health")
        with urllib.request.urlopen(request, timeout=10) as response:
            self.assertIn("application/json", response.headers.get("Content-Type", ""))


if __name__ == "__main__":
    unittest.main()
