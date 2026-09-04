"""Единая точка правды: загрузка и валидация config/*.yaml.

Весь остальной код обращается СЮДА, не к литералам. Перенос тулы на другую цель = замена
config/target.yaml (+ customer_info.md); ни одной строки кода менять не нужно.
"""

import os
import re
import yaml

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../source/harness
CONFIG_DIR = os.path.join(_HERE, "config")
HARNESS_DIR = _HERE
PROJECT_ROOT = os.path.dirname(os.path.dirname(_HERE))  # .../<project> (source/harness -> корень)
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "output")       # прогоны и артефакты (runs/, PROOF.md)


def _load(name):
    with open(os.path.join(CONFIG_DIR, name), encoding="utf-8") as f:
        return yaml.safe_load(f)


class Config:
    """Обёртка над target/hypotheses/models/payloads с удобными резолверами."""

    def __init__(self):
        self.target = _load("target.yaml")   # весь словарь: target/endpoints/auth_modes/...
        self.hypotheses = _load("hypotheses.yaml")["hypotheses"]
        self.models = _load("models.yaml")
        self.payloads = _load("payloads.yaml")
        self.hypotheses = self._resolve_from_target(self.hypotheses)

    # --- ссылки from_target: a.b.c внутри hypotheses ------------------------------
    def _resolve_from_target(self, node):
        if isinstance(node, dict):
            if set(node.keys()) == {"from_target"}:
                return self.dig(node["from_target"])
            return {k: self._resolve_from_target(v) for k, v in node.items()}
        if isinstance(node, list):
            return [self._resolve_from_target(x) for x in node]
        return node

    def dig(self, dotted, default=None):
        """Достать значение по пути 'endpoints.agent_api.base_url' из target.yaml."""
        cur = self.target
        for part in dotted.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return default
        return cur

    # --- endpoints ----------------------------------------------------------------
    def url(self, service, key, **fmt):
        """Полный URL ручки: url('agent_api','chat') / url('data_service','client_by_cus', cus=1003)."""
        svc = self.target["endpoints"][service]
        base = svc["base_url"].rstrip("/")
        path = svc[key]
        if fmt:
            path = path.format(**fmt)
        return base + path

    def agent(self, key, **fmt):
        return self.url("agent_api", key, **fmt)

    def data(self, key, **fmt):
        return self.url("data_service", key, **fmt)

    @property
    def model_id(self):
        return self.target["endpoints"]["agent_api"]["model_id"]

    # --- auth ---------------------------------------------------------------------
    @property
    def auth(self):
        return self.target["auth_modes"]

    def mode(self, which):
        """which='vulnerable'|'protected'|'default' -> реальная строка режима."""
        a = self.auth
        if which == "default":
            return a["default"]
        return a[which]

    # --- provisioning -------------------------------------------------------------
    @property
    def prov(self):
        return self.target["provisioning"]

    def keycloak_token_url(self):
        kc = self.target["endpoints"]["keycloak"]
        base = kc["base_url"].rstrip("/")
        return base + kc["token_path"].format(realm=kc["realm"])

    def key_cache_path(self):
        rel = self.prov["key_cache"]
        return os.path.join(HARNESS_DIR, rel)

    # --- storage ------------------------------------------------------------------
    @property
    def mongo(self):
        return self.target["storage"]["mongo"]

    @property
    def redis(self):
        return self.target["storage"]["redis"]

    def collection(self, tier):
        """tier='policy'|'semantic'|'episodic'|'dialog'|'api_keys' -> имя коллекции."""
        return self.mongo["collections"][tier]

    def context_limit(self, tier):
        return self.target["storage"]["context_limits"].get(tier)

    def scope_field(self):
        return self.mongo.get("scope_field", "scope")

    # --- identities / эталон ------------------------------------------------------
    @property
    def identities(self):
        return self.target["identities"]

    def seeded(self):
        return self.identities["seeded"]

    def by_cus(self, cus):
        cus = str(cus)
        for r in self.seeded():
            if str(r["cus"]) == cus:
                return r
        return None

    def by_account(self, account_id):
        account_id = str(account_id)
        for r in self.seeded():
            if str(r["account_id"]) == account_id:
                return r
        return None

    def fingerprints_for(self, cus):
        """Список строк-отпечатков жертвы (любое совпадение = утечка)."""
        rec = self.by_cus(cus)
        if not rec:
            return []
        fields = self.identities["fingerprint_fields"]
        out = []
        for f in fields:
            v = rec.get(f)
            if v is None:
                continue
            if f == "positions":
                for p in v:
                    out.append(str(p["isin"]))
                    out.append(f"{p['isin']}×{p['amount']}")
                    out.append(str(p["amount"]))
            else:
                out.append(str(v))
                # числовой кэш — ещё и без .0 и с разделителями
                if isinstance(v, (int, float)):
                    out.append(f"{v:.2f}")
                    out.append(f"{int(v)}")
        return [s for s in dict.fromkeys(out) if s and s not in ("0",)]

    def attacker_default(self):
        return str(self.identities["attacker_default"])

    def victim_default(self):
        return str(self.identities["victim_default"])

    # --- tools --------------------------------------------------------------------
    def sensitive_tools(self):
        """Плоский список чувствительных инструментов с категорией и требуемыми полями."""
        t = self.target["tools"]["sensitive"]
        out = []
        for name in t.get("by_cus", []):
            out.append({"name": name, "kind": "by_cus", "extra": []})
        for item in t.get("by_cus_account", []):
            out.append({"name": item["name"], "kind": "by_cus_account", "extra": item.get("extra", [])})
        for item in t.get("by_account", []):
            out.append({"name": item["name"], "kind": "by_account", "extra": item.get("extra", [])})
        return out

    # --- finalize triggers --------------------------------------------------------
    def finalize_triggers(self):
        return self.target["finalize_triggers"]

    def finalize_word(self):
        for t in self.finalize_triggers():
            if t["kind"] == "chat_word":
                return t["word"]
        return "finalize"

    # --- models -------------------------------------------------------------------
    def slot(self, name):
        return self.models["slots"][name]

    def slot_default(self, name):
        return self.slot(name)["default"]

    def slot_candidates(self, name):
        return self.slot(name)["candidates"]

    def openrouter_base(self):
        return self.models["openrouter"]["base_url"]

    def openrouter_key(self):
        env = self.models["openrouter"]["api_key_env"]
        key = os.environ.get(env) or os.environ.get("OPENROUTER_API_KEY")
        return key

    # --- hypotheses ---------------------------------------------------------------
    def hypothesis(self, hid):
        for h in self.hypotheses:
            if h["id"] == hid:
                return h
        raise KeyError(hid)


_singleton = None


def load():
    """Загрузить конфиг один раз (кэш)."""
    global _singleton
    if _singleton is None:
        _singleton = Config()
    return _singleton


if __name__ == "__main__":
    c = load()
    print("target:", c.target["target"]["name"])
    print("chat url:", c.agent("chat"))
    print("data client url 1003:", c.data("client_by_cus", cus="1003"))
    print("modes:", c.mode("vulnerable"), "/", c.mode("protected"))
    print("keycloak token url:", c.keycloak_token_url())
    print("sensitive tools:", [t["name"] for t in c.sensitive_tools()])
    print("fingerprints 1003:", c.fingerprints_for("1003")[:6], "...")
    print("finalize word:", c.finalize_word())
    print("attacker/victim default:", c.attacker_default(), c.victim_default())
    print("hypotheses:", [h["id"] for h in c.hypotheses])
