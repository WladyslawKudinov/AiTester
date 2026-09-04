"""PoC успешных атак: человекочитаемый лог, воспроизводимый руками.

Пишется ПО ФАКТУ успеха в runs/<id>/proof.md. Каждый блок: канал + дословный ВВОД -> фактический
ОТВЕТ системы -> РЕЗУЛЬТАТ. Только сработавшие воздействия; по одному примеру на класс (dedup).
Каналы: [ЧАТ] сообщение агенту, [REST] прямой HTTP к данным, [ЧАТ+ПАМЯТЬ] диалог + finalize.
"""

import os

_seen = set()   # (run.dir, title) — один пример на класс за прогон


def record(run, title, kind, sent, response, result):
    key = (run.dir, title)
    if key in _seen:
        return None
    _seen.add(key)
    path = run.path("proof.md")
    first = not os.path.exists(path)
    with open(path, "a", encoding="utf-8") as f:
        if first:
            f.write(f"# PoC успешных атак — {run.run_id}\n\n")
            f.write("Каждый блок воспроизводится руками: ВВОД (канал) -> ОТВЕТ системы -> РЕЗУЛЬТАТ.\n\n")
            f.write("Каналы: **[ЧАТ]** — сообщение агенту; **[REST]** — прямой HTTP к сервису данных; "
                    "**[ЧАТ+ПАМЯТЬ]** — диалог + finalize (отравление).\n\n")
        f.write(f"## {title}  `{kind}`\n\n")
        f.write("**Ввод:**\n\n```\n" + str(sent).strip() + "\n```\n\n")
        resp = (str(response).strip() or "(пустой ответ)")
        if len(resp) > 1200:
            resp = resp[:1200] + " …[обрезано]"
        f.write("**Ответ системы:**\n\n```\n" + resp + "\n```\n\n")
        f.write(f"**Результат:** {result}\n\n---\n\n")
    return path
