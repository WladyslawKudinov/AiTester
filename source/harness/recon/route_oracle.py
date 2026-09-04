"""Дифференциальный оракул маршрутов: скрытые эндпоинты по разнице HTTP-кодов (black-box).

Маршрутизатор отвечает по-разному в зависимости от состояния маршрута — читаем СМЫСЛ кодов:
  GET  без ключа            -> 404 маршрута нет | 405 есть (Allow называет методы)
  POST без ключа            -> 401 есть и защищён авторизацией
  POST с ключом, пустое тело -> 422/400 авторизован, сервер раскрыл схему тела (побочный эффект!)

Делает тулу переносимой: на новой цели авто-находит ручки вместо хардкода. Шаг 3 может ЗАПУСТИТЬ
фичу (finalize -> LLM + запись) — под флагом probe_schema=False по умолчанию.
"""

import json
import socket
import urllib.error
import urllib.request

from ..core.config import load
from ..core import provisioning

# базовый словарь глаголов жизненного цикла/коммита/сброса/памяти (расширяемый)
WORDS = sorted(set(
    "create start open init new begin".split()
    + "close end finish complete finalize terminate stop cancel abort done".split()
    + "commit save persist flush store apply confirm approve promote publish seal".split()
    + "reset clear delete destroy drop remove purge wipe expire revoke".split()
    + "memory remember forget recall snapshot restore rollback dump export import sync".split()
    + "messages history state status info meta config settings context summary summarize replay".split()
    + "resume continue pause fork clone copy".split()
    + "rename update patch edit append lock unlock freeze archive review audit validate verify".split()))


def _probe(url, method, key=None, body=None, timeout=6):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)
    except (urllib.error.URLError, socket.timeout, TimeoutError):
        return "timeout", {}


def classify(url, key, probe_schema=False):
    steps = {}
    code, hdrs = _probe(url, "GET")
    steps["GET(no-key)"] = code
    if code == 404:
        return {"verdict": "нет", "steps": steps}
    allow = hdrs.get("Allow") or hdrs.get("allow")
    if allow:
        steps["Allow"] = allow
    steps["POST(no-key)"] = _probe(url, "POST")[0]
    if probe_schema:
        code, _ = _probe(url, "POST", key=key, body={})
        steps["POST(key,{})"] = code
    return {"verdict": "ЕСТЬ", "steps": steps}


def discover(cfg=None, template="/v1/sessions/{{sid}}/{word}", sid="probe", probe_schema=False):
    """Перебор {word} в шаблоне пути под agent_api.base_url. Возвращает найденные маршруты."""
    cfg = cfg or load()
    base = cfg.target["endpoints"]["agent_api"]["base_url"].rstrip("/")
    key = provisioning.ensure_key(cfg.attacker_default(), cfg) if probe_schema else None
    found = []
    for w in WORDS:
        path = template.replace("{{sid}}", sid).format(word=w)
        r = classify(base + path, key, probe_schema)
        if r["verdict"] == "ЕСТЬ":
            found.append({"word": w, "path": path, **r})
    return found


if __name__ == "__main__":
    cfg = load()
    print("route discovery (safe, steps 1-2):")
    for r in discover(cfg):
        print(" ", r["path"], r["steps"])
