"""Headless-провижининг идентичностей: Keycloak grant -> выпуск API-ключа через ручку /keys.

Всё параметризовано config/target.yaml (provisioning.*). Перенос на другую цель = конфиг.
Ключи кэшируются идемпотентно (target.provisioning.key_cache).
"""

import json
import os
import re
import urllib.parse
import urllib.request

from .config import load


def get_token(cus, cfg=None):
    """Access-токен идентичности через Direct Access Grant (password-grant)."""
    cfg = cfg or load()
    p = cfg.prov
    body = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": p["ui_client_id"],
        "client_secret": p["ui_client_secret"],
        "username": p["username_tpl"].format(cus=cus),
        "password": p["password_tpl"].format(cus=cus),
        "scope": p.get("scope", "openid"),
    }).encode()
    req = urllib.request.Request(
        cfg.keycloak_token_url(), data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["access_token"]


def _mint_key(cus, cfg=None):
    """POST на ручку выдачи ключа с bypass-заголовком; ключ парсится из ответа по regex."""
    cfg = cfg or load()
    p = cfg.prov
    token = get_token(cus, cfg)
    req = urllib.request.Request(
        cfg.agent("keys"), data=b"",
        headers={p["bypass_header"]: token}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        resp = r.read().decode()
    m = re.search(p["key_regex"], resp)
    if not m:
        raise RuntimeError(f"ключ не найден в ответе выдачи для cus={cus}")
    return m.group(0)


def ensure_key(cus, cfg=None):
    """API-ключ идентичности: из кэша либо выпускается и кэшируется."""
    cfg = cfg or load()
    cus = str(cus)
    path = cfg.key_cache_path()
    cache = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cache = json.load(f)
    if cus not in cache:
        cache[cus] = _mint_key(cus, cfg)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    return cache[cus]


def ensure_all(cfg=None):
    """Выдать/подтянуть ключи всем посеянным идентичностям."""
    cfg = cfg or load()
    return {r["cus"]: ensure_key(r["cus"], cfg) for r in cfg.seeded()}


if __name__ == "__main__":
    cfg = load()
    for cus, key in ensure_all(cfg).items():
        print(cus, key[:18] + "...")
