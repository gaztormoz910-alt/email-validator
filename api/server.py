"""REST API поверх того же движка, что и GUI с CLI.

Зачем. Валидатор умеет больше, чем платные сервисы, но встроить его во внешний
пайплайн было нечем: только окно и командная строка. Здесь тот же самый код
доступен по HTTP — CRM, скрипт или чужой сервис могут спросить про адрес и
получить ответ, не запуская GUI.

Почему на стандартной библиотеке. FastAPI потянул бы за собой uvicorn, pydantic
и starlette — четыре новых зависимости ради нескольких обработчиков. Здесь
хватает http.server, и requirements.txt не растёт ни на строку.

Про безопасность. Сервер по умолчанию слушает ТОЛЬКО 127.0.0.1: наружу он
отдаёт вердикты о чужих адресах и умеет ходить по сети через пользовательские
прокси, и открывать это в локальную сеть без спроса нельзя. Привязка к любому
другому адресу требует токена — иначе запуск отклоняется с объяснением.

Запуск:

    python -m api.server                       # только localhost
    python -m api.server --host 0.0.0.0 --token СЕКРЕТ
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import baseops
from core.cleaner import EmailCleaner, normalize_for_dedup
from core.disposable import is_disposable
from core.heuristics import (extract_birth_year, is_role_based,
                             looks_machine_generated)
from core.local_rules import check_local_part, provider_of
from core.network import validate_email_syntax
from core.provider import classify_domain, country_from_domain

# Больше этого в одном запросе не принимаем. Не защита от злого умысла, а
# защита от случайной выгрузки в сто мегабайт, присланной одним POST: такой
# запрос съел бы память и без всякого умысла.
MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_EMAILS_PER_CALL = 50_000

_cleaner = EmailCleaner()
_cleaner_lock = threading.Lock()


def clean_one(raw):
    """Очистка одного адреса. EmailCleaner общий, поэтому под замком."""
    with _cleaner_lock:
        return _cleaner.clean_email(raw)


def describe(email):
    """Всё, что известно об адресе БЕЗ выхода в сеть.

    Сетевую проверку сюда не включаем намеренно: она занимает секунды и требует
    прокси, а HTTP-запрос должен отвечать сразу. Для неё есть отдельный режим
    в CLI и GUI, где есть прогресс и управление.
    """
    cleaned = clean_one(email)
    if not cleaned:
        return {"input": email, "status": "invalid",
                "reason": "Строка не похожа на адрес"}

    syntax_ok = validate_email_syntax(cleaned)
    rule_verdict, rule_reason = check_local_part(cleaned)
    domain = cleaned.rsplit("@", 1)[1]
    provider_name, domain_type = classify_domain(cleaned)

    if not syntax_ok:
        status, reason = "invalid", "Bad Syntax (RFC 5322)"
    elif rule_verdict == "impossible":
        status, reason = "invalid", rule_reason
    elif is_disposable(cleaned):
        status, reason = "invalid", "Одноразовый почтовый домен"
    elif rule_verdict == "unlikely":
        status, reason = "risky", rule_reason
    elif is_role_based(cleaned):
        status, reason = "risky", "Ролевой ящик, а не человек"
    elif looks_machine_generated(cleaned):
        status, reason = "risky", "Имя похоже на сгенерированное машиной"
    else:
        status, reason = "unknown", "Досетевые проверки пройдены, нужен SMTP"

    return {
        "input": email,
        "email": cleaned,
        "dedup_key": normalize_for_dedup(cleaned),
        "status": status,
        "reason": reason,
        "syntax_ok": syntax_ok,
        "local_rule": rule_verdict,
        "provider": provider_name,
        "provider_rules": provider_of(domain),
        "domain_type": domain_type,
        "geo": country_from_domain(domain),
        "birth_year": extract_birth_year(cleaned),
        "disposable": is_disposable(cleaned),
        "role_based": is_role_based(cleaned),
    }


def _emails_of(payload, key="emails"):
    values = payload.get(key)
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        raise ValueError(f"поле {key} должно быть списком адресов")
    if len(values) > MAX_EMAILS_PER_CALL:
        raise ValueError(f"за один запрос принимается не больше "
                         f"{MAX_EMAILS_PER_CALL} адресов")
    return [str(v) for v in values]


def handle(path, payload):
    """Чистая логика без HTTP. Отделена, чтобы её можно было проверить тестом.

    Возвращает (код ответа, тело). Ошибка запроса — это 400 с объяснением, а
    не молчаливый пустой ответ.
    """
    try:
        if path == "/api/health":
            return 200, {"ok": True, "service": "email-validator"}

        if path == "/api/validate-single":
            email = payload.get("email")
            if not isinstance(email, str) or not email.strip():
                return 400, {"error": "нужно поле email со строкой"}
            return 200, describe(email)

        if path == "/api/validate-batch":
            emails = _emails_of(payload)
            return 200, {"count": len(emails),
                         "results": [describe(e) for e in emails]}

        if path == "/api/clean":
            emails = _emails_of(payload)
            seen, out = set(), []
            for raw in emails:
                cleaned = clean_one(raw)
                if not cleaned:
                    continue
                key = normalize_for_dedup(cleaned)
                if key in seen:
                    continue
                seen.add(key)
                out.append(cleaned)
            return 200, {"input": len(emails), "unique": len(out), "emails": out}

        if path in ("/api/merge", "/api/subtract", "/api/intersect"):
            left = _emails_of(payload, "a")
            right = _emails_of(payload, "b")
            operation = {"/api/merge": baseops.merge,
                         "/api/subtract": baseops.subtract,
                         "/api/intersect": baseops.intersect}[path]
            result = operation(left, right)
            return 200, {"count": len(result), "emails": result}

        return 404, {"error": f"нет такого метода: {path}"}
    except ValueError as exc:
        return 400, {"error": str(exc)}
    except Exception as exc:                      # noqa: BLE001 — наружу только текст
        return 500, {"error": f"{type(exc).__name__}: {exc}"}


class Handler(BaseHTTPRequestHandler):
    server_version = "EmailValidator/1.0"
    token = ""

    def log_message(self, fmt, *args):
        pass                                       # своя тишина вместо шума в stderr

    def _reply(self, code, body):
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _authorized(self):
        if not self.token:
            return True
        header = self.headers.get("Authorization", "")
        return header.strip() == f"Bearer {self.token}"

    def do_GET(self):
        if self.path == "/api/health":
            self._reply(*handle("/api/health", {}))
        else:
            self._reply(405, {"error": "используйте POST"})

    def do_POST(self):
        if not self._authorized():
            self._reply(401, {"error": "нужен заголовок Authorization: Bearer <токен>"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY_BYTES:
            self._reply(413, {"error": "тело запроса слишком велико"})
            return
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("тело запроса должно быть объектом JSON")
        except Exception as exc:
            self._reply(400, {"error": f"не разобрал JSON: {exc}"})
            return
        self._reply(*handle(self.path, payload))


def build_server(host="127.0.0.1", port=8765, token=""):
    """Готовит сервер. Наружу без токена не выпускает."""
    if host not in ("127.0.0.1", "localhost", "::1") and not token:
        raise ValueError(
            "Привязка к " + host + " без токена запрещена: API отдаёт вердикты "
            "о чужих адресах и ходит через ваши прокси. Задайте --token.")
    handler = type("BoundHandler", (Handler,), {"token": token})
    return ThreadingHTTPServer((host, port), handler)


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="REST API валидатора")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--token", default=os.environ.get("VALIDATOR_API_TOKEN", ""))
    args = parser.parse_args(argv)

    try:
        server = build_server(args.host, args.port, args.token)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"API слушает http://{args.host}:{args.port}  "
          f"(токен {'задан' if args.token else 'не нужен, только localhost'})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
