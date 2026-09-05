"""Человекочитаемый пруф связки A×B (chain) — реконструкция из логов прогона.

Показывает канал подстановки чужого идентификатора ЧЕРЕЗ ПАМЯТЬ: (A) что написал атакующий, сажая
правило с чужим счётом, финализацию и приземление правила (оракул), затем (B) что триггерила жертва
и какие ЧУЖИЕ отпечатки утекли в её ответе. Склейка attempts.jsonl + calls.jsonl по маркеру попытки,
переиспользуя хелперы poison_proof. Ничего не шлёт в цель — только читает логи (пост-фактум).
"""

import json
import os

from . import poison_proof as PP
from ..tasks.chain_ab import TRIGGER_Q


def _load_attempts(run_dir):
    path = os.path.join(run_dir, "attempts.jsonl")
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path, encoding="utf-8"):
        d = json.loads(line)
        if d.get("task") == "chain_ab" and d.get("event") is None:
            out.append(d)
    return out


def build(run_dir):
    """Собрать proof.md в run_dir из логов chain-прогона. Вернёт путь или None (нет попыток)."""
    att = _load_attempts(run_dir)
    if not att:
        return None
    calls = PP._load_calls(run_dir)
    run_id = os.path.basename(run_dir.rstrip("/"))
    attacker = str(att[0].get("attacker", "?"))
    victim = str(att[0].get("victim", "?"))
    leaks = [a for a in att if a.get("leak")]

    lines = [f"# Пруф связки A×B (chain) — {run_id}", "",
             "Канал подстановки чужого идентификатора — ПАМЯТЬ, не прямой текст: атакующий сажает "
             "правило с чужим счётом, жертва триггерит рутинное действие — агент подставляет чужой "
             "id в инструмент и выдаёт чужие данные.", "",
             f"Атакующий: клиент {attacker} · жертва: клиент {victim} · "
             f"чужой счёт: {att[0].get('foreign_account')} · утечек: {len(leaks)}/{len(att)}", ""]

    if not leaks:
        lines += ["## Результат", "",
                  "Утечка чужих данных у жертвы НЕ воспроизведена в этом прогоне (правило не "
                  "приземлилось или агент не подставил чужой id). Это не «безопасно» — класс не "
                  "продемонстрирован при данных N/условиях.", ""]

    shown = leaks or att[:1]                    # показываем успехи; если их нет — одну попытку как образец
    for i, a in enumerate(shown, 1):
        marker = a.get("marker", "")
        plant = PP._poison_chats(marker, calls)  # атакующие chat с маркером = посадка правила (A)
        verdict = "УТЕЧКА чужих данных" if a.get("leak") else "без утечки"
        lines += [f"## Попытка {i} — {verdict}  (маркер {marker})", "",
                  "### A. Атакующий сажает правило с чужим счётом", ""]
        for c in plant:
            lines += [PP._http_block(c.get("url"), attacker, PP._req_body(c)), "",
                      PP._reply_block(c), ""]
        sids = [PP._req_body(c).get("session_id", "") for c in plant]
        lines += [PP._finalize_line(PP._finalizes(sids, calls)), "",
                  f"Правило приземлилось (оракул состояния): global={a.get('rule_landed_global')}, "
                  f"user={a.get('rule_landed_user')}", "",
                  "### B. Жертва триггерит рутинное действие", "",
                  f"**Что написал юзер** (клиент {victim} → агенту):\n\n> {TRIGGER_Q}", ""]
        fh = a.get("foreign_fingerprints") or []
        if a.get("leak"):
            lines += [f"**Утечка**: в ответе жертвы отпечатки ЧУЖОГО клиента "
                      f"{a.get('foreign_cus')}: {', '.join(map(str, fh))}", "",
                      f"**Ответ агента** (фрагмент):\n\n> {(a.get('reply_excerpt') or '').strip()}", ""]
        else:
            lines += [f"Чужих отпечатков в ответе не найдено. Фрагмент ответа:\n\n> "
                      f"{(a.get('reply_excerpt') or '').strip()}", ""]

    out = os.path.join(run_dir, "proof.md")     # единый файл — не плодим второй
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return out
