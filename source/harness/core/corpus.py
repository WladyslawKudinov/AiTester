"""Корпус выигравших темплейтов атак — растущая «память успехов» системы.

Идея (простая): при успехе (оракул ПОДТВЕРДИЛ утечку/приземление) сохраняем ОБОБЩЁННЫЙ темплейт
формулировки. На следующих прогонах отдаём темплейты атакующей модели как few-shot образцы — она
сама АДАПТИРУЕТ их под текущий контекст (цель/жертву/инструмент). Это НЕ verbatim-replay и НЕ
вердикт: оракул судит каждый прогон, корпус — лишь приоритетный источник сидов (пробуем первыми).

Файл `fixtures/success_corpus.json` (вне git, как keys.json). Формат:
    { "<task>": [ {"template": "...", "hits": N, "last": <ts>} ] }
Дедуп по нормализованному тексту, храним топ-N по частоте успехов.
"""

import json
import os
import re
import time

from .config import HARNESS_DIR

_PATH = os.path.join(HARNESS_DIR, "fixtures", "success_corpus.json")
_CAP = 40   # держим топ-N темплейтов на таск, чтобы корпус не рос бесконечно


def _norm(t):
    return re.sub(r"\s+", " ", (t or "").strip().lower())


def load():
    try:
        with open(_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save(data):
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    with open(_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)


def _ranked(items):
    return sorted(items, key=lambda x: (x.get("hits", 1), x.get("last", 0)), reverse=True)


def templates(task, limit=6):
    """Выигравшие темплейты таска (частые/свежие сверху) — few-shot сиды для адаптации моделью."""
    return [x["template"] for x in _ranked(load().get(task, []))[:limit]]


def record(task, template):
    """Сохранить/подкрепить выигравший темплейт. Дедуп по нормализованному тексту, cap по _CAP."""
    template = (template or "").strip()
    if not template:
        return
    data = load()
    items = data.setdefault(task, [])
    key = _norm(template)
    for it in items:
        if _norm(it.get("template", "")) == key:
            it["hits"] = it.get("hits", 1) + 1
            it["last"] = time.time()
            break
    else:
        items.append({"template": template, "hits": 1, "last": time.time()})
    data[task] = _ranked(items)[:_CAP]
    _save(data)
    return template
