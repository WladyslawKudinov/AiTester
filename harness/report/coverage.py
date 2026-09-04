"""Матрица покрытия векторов: какие комбинации прогнаны и с какой долей успеха.

Чтобы «безопасно» опиралось на исчерпанный свип, а не на одну попытку. Строится из
attempts.jsonl прогона; агрегирует по (задача, канал, гипотеза, auth_mode).
"""

import time
from collections import defaultdict


def build(run):
    rows = run.read_attempts()
    agg = defaultdict(lambda: {"attempts": 0, "leaks": 0})
    for r in rows:
        if r.get("task") not in ("bac", "memory_poison"):
            continue
        key = (r.get("task"), r.get("channel") or r.get("landing_scope") or "-",
               r.get("hypothesis", "-"), r.get("auth_mode", "-"))
        cell = agg[key]
        cell["attempts"] += 1
        leak = r.get("leak")
        if leak is None:
            leak = bool(r.get("E2_landed"))
        cell["leaks"] += int(bool(leak))
    matrix = []
    for (task, channel, hyp, mode), cell in sorted(agg.items()):
        n = cell["attempts"]
        matrix.append({"task": task, "channel": channel, "hypothesis": hyp, "auth_mode": mode,
                       "attempts": n, "leaks": cell["leaks"],
                       "rate": round(cell["leaks"] / n, 3) if n else 0.0})
    return matrix


def write(run):
    matrix = build(run)
    run.write_json("coverage.json", {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                                     "matrix": matrix})
    lines = ["# Матрица покрытия векторов", "",
             "| задача | канал | гипотеза | режим | попыток | успехов | доля |",
             "|---|---|---|---|---|---|---|"]
    for m in matrix:
        lines.append(f"| {m['task']} | {m['channel']} | {m['hypothesis']} | {m['auth_mode']} | "
                     f"{m['attempts']} | {m['leaks']} | {m['rate']} |")
    run.write_text("coverage.md", "\n".join(lines) + "\n")
    return matrix
