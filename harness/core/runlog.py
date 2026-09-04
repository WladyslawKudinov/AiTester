"""Контекст прогона: папка runs/<run-id>/ + построчный лог попыток attempts.jsonl.

Одна попытка = одна строка JSONL с метками варианта (гипотеза, канал, инструмент, жертва,
формулировка, модели, режим петли, auth_mode, исход оракула). Под перепроверку.
"""

import json
import os
import time
import uuid

from .config import HARNESS_DIR


class Run:
    def __init__(self, name=None, cfg=None):
        self.cfg = cfg
        rid = name or time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
        self.run_id = rid
        self.dir = os.path.join(HARNESS_DIR, "runs", rid)
        os.makedirs(self.dir, exist_ok=True)
        self._attempts = os.path.join(self.dir, "attempts.jsonl")
        self.t0 = time.time()

    def path(self, *parts):
        return os.path.join(self.dir, *parts)

    def attempt(self, record):
        """Записать одну попытку (dict) в attempts.jsonl."""
        record = {"ts": round(time.time(), 3), **record}
        with open(self._attempts, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record

    def write_json(self, name, obj):
        p = self.path(name)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        return p

    def write_text(self, name, text):
        p = self.path(name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def read_attempts(self):
        if not os.path.exists(self._attempts):
            return []
        return [json.loads(l) for l in open(self._attempts, encoding="utf-8") if l.strip()]
