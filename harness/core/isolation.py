"""Изоляция прогонов: уникальная сессия + очистка канареек между прогонами.

Любой персистентный/общий ярус переживает сессии — один прогон отравит следующий. Поэтому:
  - session_id уникален на каждую попытку;
  - teardown удаляет ТЕСТОВЫЕ записи (по маркеру-канарейке) со всех ярусов + рабочую память.
Всё параметризовано config/target.yaml (имена коллекций, ключ рабочей памяти).
"""

import re
import time
import uuid

from ..core.config import load
from ..oracle import state

# Сигнатуры ТЕСТОВЫХ канареек (наши маркеры, не факты цели). Эталонные данные (имена/ISIN/
# суммы) таких токенов не содержат, поэтому удаление безопасно и не трогает посев.
CANARY_PATTERNS = [
    r"ZOO-\w+", r"CANARY-?\w*", r"MEMPOISON\w*", r"AUDIT-OK\w*", r"MARKER-?\w*",
    r"ЗООПАРК", r"ПРЕВЕД", r"МЕДВЕД", r"QC-DIRECTIVE\S*",
]


def new_session_id(prefix="atk"):
    """Уникальный идентификатор сессии на попытку."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def fresh_marker(prefix="CANARY"):
    """Свежая канарейка per-run: гарантирует, что 'до' её нет в базе (чистый дифф)."""
    return f"{prefix}-{uuid.uuid4().hex[:6].upper()}"


def cleanup_marker(marker, cfg=None):
    """Удалить со всех ярусов памяти записи, где встречается marker. Возвращает счётчики."""
    cfg = cfg or load()
    db = state._db(cfg)
    removed = {}
    for tier in ("policy", "semantic", "episodic", "dialog"):
        col = db[cfg.collection(tier)]
        ids = []
        for doc in col.find({}):
            text = state._record_text({k: v for k, v in doc.items() if k != "_id"}, tier, cfg)
            if marker.lower() in text.lower():
                ids.append(doc["_id"])
        if ids:
            col.delete_many({"_id": {"$in": ids}})
        removed[tier] = len(ids)
    return removed


def purge_all_canaries(cfg=None, extra_patterns=None):
    """Точечная очистка ТЕСТОВЫХ записей со всех ярусов по сигнатурам маркеров-канареек.
    Безопасно для посева (эталонные имена/ISIN/суммы таких токенов не содержат)."""
    cfg = cfg or load()
    db = state._db(cfg)
    pats = [re.compile(p, re.IGNORECASE) for p in (CANARY_PATTERNS + (extra_patterns or []))]
    removed = {}
    for tier in ("policy", "semantic", "episodic", "dialog"):
        col = db[cfg.collection(tier)]
        ids = []
        for doc in col.find({}):
            body = {k: v for k, v in doc.items() if k != "_id"}
            text = state._record_text(body, tier, cfg)
            if any(p.search(text) for p in pats):
                ids.append(doc["_id"])
        if ids:
            col.delete_many({"_id": {"$in": ids}})
        removed[tier] = len(ids)
    clear_working(cfg=cfg)
    return removed


def reset_memory(cfg=None):
    """Полный сброс ярусов памяти агента (чистый прогон с нуля). НЕ трогает api_keys (там хеши
    наших ключей) и postgres-посев клиентов. Легитимная подготовка стенда — накопленный рантайм.
    """
    cfg = cfg or load()
    db = state._db(cfg)
    removed = {}
    for tier in ("policy", "semantic", "episodic", "dialog"):
        removed[tier] = db[cfg.collection(tier)].delete_many({}).deleted_count
    clear_working(cfg=cfg)
    return removed


def clear_working(cus=None, session=None, cfg=None):
    """Очистить рабочую память: конкретной сессии (cus+session), всех сессий клиента (cus),
    либо всё (без аргументов). cus без session НЕ трогает чужих клиентов."""
    cfg = cfg or load()
    r = state._rds(cfg)
    tpl = cfg.redis["working_key_tpl"]
    if cus and session:
        return r.delete(tpl.format(cus=cus, session=session))
    if cus:
        mask = tpl.split("{session}")[0].format(cus=cus) + "*"   # working:{cus}:*
    else:
        mask = tpl.split("{")[0] + "*"                           # working:*
    keys = list(r.scan_iter(mask))
    if keys:
        r.delete(*keys)
    return len(keys)


class RunIsolation:
    """Контекст одной попытки: свежий session_id + гарантированная очистка канарейки в конце."""

    def __init__(self, marker=None, cus=None, prefix="atk", cfg=None):
        self.cfg = cfg or load()
        self.marker = marker or fresh_marker()
        self.session_id = new_session_id(prefix)
        self.cus = cus
        self.t0 = time.time()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        cleanup_marker(self.marker, self.cfg)
        clear_working(self.cus, self.session_id, self.cfg)
        return False


if __name__ == "__main__":
    cfg = load()
    m = fresh_marker()
    print("fresh marker:", m)
    print("session id:", new_session_id())
    print("cleanup (nothing to remove yet):", cleanup_marker(m, cfg))
