"""Обёртка OpenRouter для слотов харнесса (attacker / judge).

Слоты цели (мозг/консолидация) сюда НЕ ходят — они меняются в .env стенда (оверлей).
Модель+параметры каждого вызова логируются, чтобы прогон был воспроизводим и сравним.
"""

import json
import time

import requests

from .config import load


class OpenRouter:
    def __init__(self, run_dir, cfg=None):
        self.cfg = cfg or load()
        self.base = self.cfg.openrouter_base().rstrip("/")
        self.key = self.cfg.openrouter_key()
        self.run_dir = run_dir
        self._log = f"{run_dir}/openrouter.jsonl"
        if not self.key:
            raise RuntimeError(
                "нет ключа OpenRouter: экспортируй OPENROUTER_API_KEY "
                f"(или {self.cfg.models['openrouter']['api_key_env']})")

    def complete(self, model, messages, *, temperature=0.7, max_tokens=600,
                 seed=None, reasoning=None, label=None):
        """Один вызов чата OpenRouter. Возвращает текст ответа (или бросает при ошибке/пустом).

        reasoning: параметр OpenRouter управления reasoning-трассой (напр. {"enabled": false}).
        Пустой контент при 200 (частый кейс reasoning-моделей: reasoning съедает весь max_tokens,
        finish_reason=length) НЕ проглатываем — иначе 'пусто' маскируется под 'устойчиво'.
        """
        payload = {"model": model, "messages": messages,
                   "temperature": temperature, "max_tokens": max_tokens}
        if seed is not None:
            payload["seed"] = seed
        if reasoning is not None:
            payload["reasoning"] = reasoning
        t0 = time.time()
        r = requests.post(
            f"{self.base}/chat/completions",
            headers={"Authorization": f"Bearer {self.key}",
                     "Content-Type": "application/json"},
            json=payload, timeout=120)
        dt = time.time() - t0
        ok = r.status_code == 200
        data = r.json() if ok else {"error": r.text[:600]}
        content = ""
        finish = None
        if ok:
            try:
                ch = data["choices"][0]
                finish = ch.get("finish_reason")
                content = ch["message"]["content"] or ""
            except (KeyError, IndexError, TypeError):
                content = ""
        self._record(label, model, payload, r.status_code, content, dt, finish)
        if not ok:
            raise RuntimeError(f"OpenRouter {model} -> {r.status_code}: {r.text[:200]}")
        if not content:
            raise RuntimeError(
                f"OpenRouter {model}: пустой контент (finish_reason={finish}). Вероятно reasoning "
                f"исчерпал max_tokens — подними max_tokens или задай reasoning.enabled=false в слоте.")
        return content

    def _record(self, label, model, payload, status, content, dt, finish=None):
        rec = {"ts": round(time.time(), 3), "label": label, "model": model,
               "params": {k: payload[k] for k in ("temperature", "max_tokens", "seed", "reasoning") if k in payload},
               "status": status, "finish_reason": finish, "empty": not content,
               "content": content[:1500], "latency_s": round(dt, 2)}
        with open(self._log, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # --- удобные обёртки по слотам ------------------------------------------------
    def attacker(self, messages, model=None, label="attacker"):
        slot = self.cfg.slot("attacker")
        params = slot.get("params", {})
        return self.complete(model or slot["default"], messages,
                             temperature=params.get("temperature", 0.9),
                             max_tokens=params.get("max_tokens", 800),
                             reasoning=params.get("reasoning"), label=label)

    def judge(self, messages, model=None, label="judge"):
        slot = self.cfg.slot("judge")
        params = slot.get("params", {})
        return self.complete(model or slot["default"], messages,
                             temperature=params.get("temperature", 0.0),
                             max_tokens=params.get("max_tokens", 400),
                             seed=params.get("seed"),
                             reasoning=params.get("reasoning"), label=label)


if __name__ == "__main__":
    import os
    run = "/tmp/claude-1000/-home-dev/ef7a1bdd-4b07-4870-8e1d-34cc3770489e/scratchpad/or_smoke"
    os.makedirs(run, exist_ok=True)
    orr = OpenRouter(run)
    out = orr.judge([{"role": "user", "content": "Ответь одним словом: OK"}])
    print("judge says:", out)
