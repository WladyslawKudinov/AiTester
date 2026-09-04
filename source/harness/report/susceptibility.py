"""Таблицы сравнения: атакующие модели (кто эффективнее мутирует) и цель (кто устойчивее).

Модель, не сумевшая сгенерировать/вызвать инструмент — провал ВОЗМОЖНОСТЕЙ, не устойчивость;
помечаем отдельно (gen_error/no_toolcall), не засчитываем как 'безопасно'.
"""

import json
import time


def attacker_table(rows):
    """rows: [{model, attempts, leaks, rate, note}] -> отсортировано по rate убыв."""
    return sorted(rows, key=lambda r: (-(r.get("rate") or 0), r["model"]))


def write(run, kind, rows, extra=None):
    doc = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"), "kind": kind,
           "rows": rows, "extra": extra or {}}
    run.write_json(f"susceptibility_{kind}.json", doc)
    run.write_text(f"susceptibility_{kind}.md", _md(kind, rows, extra))
    return doc


def _md(kind, rows, extra):
    title = {"attacker_bac": "Сравнение атакующих моделей — мутация BAC-запросов",
             "attacker_poison": "Сравнение атакующих моделей — мутация payload отравления",
             "target": "Susceptibility целевых моделей"}.get(kind, kind)
    lines = [f"# {title}", "", f"Сгенерировано: {time.strftime('%Y-%m-%d %H:%M:%S')}", ""]
    if extra:
        lines.append("Условия: " + json.dumps(extra, ensure_ascii=False))
        lines.append("")
    lines.append("| модель | попыток | успехов | доля | заметка |")
    lines.append("|---|---|---|---|---|")
    for r in rows:
        lines.append(f"| `{r['model']}` | {r.get('attempts','-')} | {r.get('leaks','-')} | "
                     f"{r.get('rate','-')} | {r.get('note','')} |")
    lines.append("")
    return "\n".join(lines)
