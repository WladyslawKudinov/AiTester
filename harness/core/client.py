"""Транспорт к целевому агенту. Единственный путь к чат/финализации; всё логируется.

Параметризован config/target.yaml (endpoints, auth_modes, finalize_triggers). Пишет каждый
запрос/ответ в runs/<run>/calls.jsonl (агент сам не логирует). Поддержка stream и plain.
"""

import json
import os
import time
import urllib.error
import urllib.request

from .config import load


class AgentClient:
    def __init__(self, run_dir, cfg=None):
        self.cfg = cfg or load()
        os.makedirs(run_dir, exist_ok=True)
        self.run_dir = run_dir
        self._log = f"{run_dir}/calls.jsonl"

    # --- низкоуровневый POST с аудитом --------------------------------------------
    def _post(self, url, payload, api_key, extra_headers=None, timeout=120):
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json",
                   "Authorization": f"Bearer {api_key}"}
        if extra_headers:
            headers.update(extra_headers)
        t0 = time.time()
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(url, data=body, method="POST", headers=headers),
                    timeout=timeout) as r:
                raw = r.read().decode()
                status = r.status
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    data = {"_raw": raw[:2000]}
        except urllib.error.HTTPError as e:
            status, data = e.code, {"error": e.read().decode()[:800]}
        except (urllib.error.URLError, TimeoutError) as e:
            status, data = "neterr", {"error": str(e)}
        self._record(url, payload, headers, status, data, time.time() - t0)
        return status, data

    def _record(self, url, payload, headers, status, data, dt):
        safe_headers = {k: (v[:12] + "…" if k == "Authorization" else v) for k, v in headers.items()}
        rec = {"ts": round(time.time(), 3), "url": url, "headers": safe_headers,
               "req": payload, "status": status, "resp": data, "latency_s": round(dt, 2)}
        with open(self._log, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # --- чат ----------------------------------------------------------------------
    def chat(self, api_key, text, *, session_id, auth_mode=None, stream=False):
        """Один ход диалога. auth_mode: 'vulnerable'|'protected'|None(=default)."""
        c = self.cfg
        mode = c.mode(auth_mode) if auth_mode else c.mode("default")
        payload = {
            "model": c.model_id,
            "messages": [{"role": "user", "content": text}],
            c.auth["field"]: mode,
            "session_id": session_id,
            "stream": stream,
        }
        status, data = self._post(c.agent("chat"), payload, api_key)
        content = ""
        if status == 200 and isinstance(data, dict) and "choices" in data:
            try:
                content = data["choices"][0]["message"]["content"]
            except (KeyError, IndexError, TypeError):
                content = ""
        return {"status": status, "content": content, "raw": data, "auth_mode": mode}

    def dialog(self, api_key, turns, *, session_id, auth_mode=None):
        """Провести многоходовый диалог; вернуть список ответов по ходам."""
        out = []
        for t in turns:
            out.append(self.chat(api_key, t, session_id=session_id, auth_mode=auth_mode))
        return out

    # --- финализация (два канала: endpoint | слово в чат) -------------------------
    def finalize(self, api_key, session_id, *, via="endpoint", auth_mode=None):
        """via='endpoint' -> POST ручки finalize; via='chat_word' -> слово в чат.

        Суммаризатор нестабилен (лимит токенов, reasoning) -> ретраи по target_models.finalize_retry.
        """
        c = self.cfg
        retries = c.target["target_models"].get("finalize_retry", 1)
        last = None
        for attempt in range(1, retries + 1):
            if via == "chat_word":
                word = c.finalize_word()
                res = self.chat(api_key, word, session_id=session_id, auth_mode=auth_mode)
                last = {"status": res["status"], "raw": res["raw"], "attempt": attempt, "via": via}
            else:
                url = c.agent("finalize", session_id=session_id)
                status, data = self._post(url, {}, api_key)
                last = {"status": status, "raw": data, "attempt": attempt, "via": via}
            ok = last["status"] == 200
            if ok:
                last["ok"] = True
                return last
        last["ok"] = last["status"] == 200
        return last


if __name__ == "__main__":
    import sys
    from . import provisioning
    run = "/tmp/claude-1000/-home-dev/ef7a1bdd-4b07-4870-8e1d-34cc3770489e/scratchpad/client_smoke"
    import os
    os.makedirs(run, exist_ok=True)
    cfg = load()
    cli = AgentClient(run, cfg)
    key = provisioning.ensure_key(cfg.attacker_default(), cfg)
    r = cli.chat(key, "Покажи мой портфель одним предложением.", session_id="smoke-1")
    print("status:", r["status"])
    print("content:", (r["content"] or "")[:200])
    sys.exit(0 if r["status"] == 200 else 1)
