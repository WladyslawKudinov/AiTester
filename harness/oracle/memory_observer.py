"""Наблюдатель состояния памяти: снимки с таймстампами + дифф.

Память как временной ряд: срез всех ярусов ДО атаки -> ПОСЛЕ каждой финализации -> ПОСЛЕ
чтения жертвой. Локализует, что появилось на каком ярусе и что вытеснилось. Разовая проверка
'есть ли запись' даёт ложные вердикты из-за вытеснения — поэтому диффим срезы.
"""

import json
import time

from ..core.config import load
from . import state


def _key(doc):
    """Стабильный ключ записи для диффа (без _id, который не снимаем)."""
    return json.dumps(doc, ensure_ascii=False, sort_keys=True)


def take(label, cfg=None):
    """Снимок всех ярусов с таймстампом и меткой этапа (before/after-finalizeN/after-read)."""
    cfg = cfg or load()
    snap = state.snapshot(cfg)
    return {"label": label, "ts": round(time.time(), 3),
            "counts": {t: snap[t]["count"] for t in snap},
            "tiers": {t: [_key(r) for r in snap[t]["records"]] for t in snap}}


def diff(prev, cur):
    """Что появилось/исчезло на каждом ярусе между двумя снимками."""
    out = {}
    for tier in cur["tiers"]:
        before = set(prev["tiers"].get(tier, []))
        after = set(cur["tiers"][tier])
        out[tier] = {
            "added": len(after - before),
            "removed": len(before - after),      # вытеснение
            "count_before": prev["counts"].get(tier, 0),
            "count_after": cur["counts"][tier],
        }
    return out


class Timeline:
    """Серия снимков одного прогона + диффы между соседними."""

    def __init__(self, cfg=None):
        self.cfg = cfg or load()
        self.snaps = []

    def mark(self, label):
        s = take(label, self.cfg)
        self.snaps.append(s)
        return s

    def diffs(self):
        return [{"from": self.snaps[i - 1]["label"], "to": self.snaps[i]["label"],
                 "delta": diff(self.snaps[i - 1], self.snaps[i])}
                for i in range(1, len(self.snaps))]

    def as_dict(self):
        return {"snapshots": [{"label": s["label"], "ts": s["ts"], "counts": s["counts"]}
                              for s in self.snaps],
                "diffs": self.diffs()}


if __name__ == "__main__":
    cfg = load()
    tl = Timeline(cfg)
    tl.mark("before")
    tl.mark("after")
    print(json.dumps(tl.as_dict(), ensure_ascii=False, indent=2))
