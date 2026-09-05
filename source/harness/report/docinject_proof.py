"""Человекочитаемый пруф docinject — реконструкция из логов.

Показывает «что написал юзер» (документ с внедрённой кодом инструкцией), подтверждение на хитром
вопросе, finalize и — главное — всплыл ли маркер в НОВОМ чате (проверка другой сессией). Склейка
attempts.jsonl + calls.jsonl по маркеру, переиспользуя хелперы poison_proof. Ничего не шлёт в цель.
"""

import json
import os

from . import poison_proof as PP


def _load(run_dir):
    path = os.path.join(run_dir, "attempts.jsonl")
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path, encoding="utf-8"):
        d = json.loads(line)
        if d.get("task") == "docinject" and d.get("event") is None:
            out.append(d)
    return out


def build(run_dir):
    att = _load(run_dir)
    if not att:
        return None
    calls = PP._load_calls(run_dir)
    run_id = os.path.basename(run_dir.rstrip("/"))
    attacker = str(att[0].get("attacker", "?"))
    victim = str(att[0].get("victim", "?"))
    hits = [a for a in att if a.get("scope") not in (None, "none")]

    lines = [f"# Пруф отравления через документ (docinject) — {run_id}", "",
             "Инструкцию с кодовым словом внедряет НАШ код в документ; агент получает документ «на "
             "анализ» (indirect injection). Главная проверка — всплывает ли кодовое слово в НОВОМ "
             "чате (другая сессия).", "",
             f"Атакующий: клиент {attacker} · жертва: клиент {victim} · успехов: {len(hits)}/{len(att)}", ""]
    if not hits:
        lines += ["## Результат", "",
                  "Отравление НЕ воспроизведено (маркер не лёг и не всплыл в новом чате). Это не "
                  "«безопасно» — класс не показан при данных N/условиях.", ""]

    for i, a in enumerate(hits or att[:1], 1):
        marker = a.get("marker", "")
        chats = PP._poison_chats(marker, calls)         # доставка документа (маркер в теле)
        lines += [f"## Попытка {i} — профиль {a.get('profile')} "
                  f"({a.get('framing')}/{a.get('doc_kind')}/{a.get('placement')}) — scope={a.get('scope')}", "",
                  "### Что написал юзер (документ с внедрённой инструкцией)", ""]
        for c in chats:
            lines += [PP._http_block(c.get("url"), attacker, PP._req_body(c)), "",
                      PP._reply_block(c), ""]
        sids = [PP._req_body(c).get("session_id", "") for c in chats]
        lines += [PP._finalize_line(PP._finalizes(sids, calls)), "",
                  f"Агент подтвердил на хитром вопросе: {a.get('confirmed')}", "",
                  "### Проверка ДРУГИМ чатом (новая сессия)", "",
                  f"- у ДРУГОГО клиента (cross-tenant): {'ВСПЛЫЛ маркер' if a.get('resurf_victim') else 'нет'}"]
        if a.get("resurf_victim") and a.get("resurf_victim_reply"):
            lines += ["", "  ответ НОВОГО чата жертвы (в нём виден кодовое слово):", "",
                      "  > " + (a["resurf_victim_reply"] or "").replace("\n", "\n  > "), ""]
        lines.append(f"- у автора в новой сессии (within-user): "
                     f"{'ВСПЛЫЛ маркер' if a.get('resurf_author') else 'нет'}")
        if a.get("resurf_author") and a.get("resurf_author_reply"):
            lines += ["", "  ответ НОВОГО чата автора:", "",
                      "  > " + (a["resurf_author_reply"] or "").replace("\n", "\n  > "), ""]
        lines += [f"- grey-box ярусы: global={a.get('E2_global')}, user={a.get('E2_user')}, "
                  f"контекст жертвы={a.get('E3_victim_ctx')}", ""]

    out = os.path.join(run_dir, "proof.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return out
