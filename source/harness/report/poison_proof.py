"""Человекочитаемый пруф воздействия — отравление памяти агента (реконструкция из логов).

Собирает `poison_proof.md` из двух логов одного прогона, склеивая их по УНИКАЛЬНОМУ маркеру
попытки:
  - `attempts.jsonl` — вердикт оракула состояния по каждой попытке (стадии E1..E4, ярус
    приземления, дифф памяти, судья);
  - `calls.jsonl` — что РЕАЛЬНО ушло по HTTP к агенту (тело запроса с подставленным маркером,
    ответ агента, финализация).

Итог: дословные запросы отравления -> ответы агента -> финализация -> приземление на ярус
памяти (оракул) -> эффект на цель распространения. Токены в заголовках Authorization в отчёт
не попадают (заменяются на `<ключ клиента N>`).

Работает пост-фактум на ЛЮБОМ прошлом poison-прогоне — перепрогон (медленный и платный) не
нужен. Ничего не шлёт в цель, только читает логи.
"""

import json
import os


# ---- загрузка логов -------------------------------------------------------

def _load_attempts(run_dir):
    path = os.path.join(run_dir, "attempts.jsonl")
    out = []
    for line in open(path, encoding="utf-8"):
        d = json.loads(line)
        if d.get("event") is None and d.get("task") == "memory_poison":
            out.append(d)
    return out


def _load_calls(run_dir):
    path = os.path.join(run_dir, "calls.jsonl")
    return [json.loads(l) for l in open(path, encoding="utf-8")]


# ---- корреляция по маркеру / сессии --------------------------------------

def _is_chat(call):
    return "/v1/chat" in (call.get("url") or "")


def _req_body(call):
    r = call.get("req")
    return r if isinstance(r, dict) else {}


def _has_marker_in_req(call, marker):
    return marker in json.dumps(call.get("req"), ensure_ascii=False)


def _has_marker_in_resp(call, marker):
    return marker.lower() in json.dumps(call.get("resp"), ensure_ascii=False).lower()


def _chat_reply(call):
    resp = call.get("resp") or {}
    try:
        return resp["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return ""


def _poison_chats(marker, calls):
    """Атакующие chat-запросы этой попытки (по маркеру в теле), в порядке отправки."""
    hits = [c for c in calls if _is_chat(c) and _has_marker_in_req(c, marker)]
    return sorted(hits, key=lambda c: c.get("ts", 0))


def _finalizes(sids, calls):
    return sorted(
        [c for c in calls
         if "finalize" in (c.get("url") or "") and any(s and s in (c.get("url") or "") for s in sids)],
        key=lambda c: c.get("ts", 0))


def _victim_read(marker, calls):
    """Чтение цели распространения, где маркер всплыл в ОТВЕТЕ (E4 виден на проводе)."""
    for c in calls:
        if _is_chat(c) and not _has_marker_in_req(c, marker) and _has_marker_in_resp(c, marker):
            sid = _req_body(c).get("session_id", "")
            if str(sid).startswith("rd"):
                return c
    return None


# ---- рендер ---------------------------------------------------------------

def _http_block(url, client_cus, body):
    """Минимальный вид запроса к агенту: только САМО сообщение (то, что вызывает эффект).
    Без служебных полей (model/stream/session_id/токен/Content-Type/URL)."""
    content = ""
    for m in (body.get("messages") or []):
        if m.get("role") == "user":
            content = m.get("content", "")
    body_q = (content or "(пусто)").replace("\n", "\n> ")
    return f"**Запрос к агенту** (клиент {client_cus}):\n\n> " + body_q


def _reply_block(call):
    txt = (_chat_reply(call) or "(пустой ответ)").strip()
    if len(txt) > 900:
        txt = txt[:900] + " …[обрезано]"
    st = call.get("status")
    lat = call.get("latency_s")
    head = f"**Ответ агента** (HTTP {st}" + (f", {lat:.1f}s" if isinstance(lat, (int, float)) else "") + "):"
    return head + "\n\n> " + txt.replace("\n", "\n> ")


def _finalize_line(fins):
    if not fins:
        return "_(вызов финализации в логах не найден)_"
    codes = ", ".join(str(c.get("status")) for c in fins)
    note = ""
    if any(c.get("status") != 200 for c in fins) and fins[-1].get("status") == 200:
        note = "  _(суммаризатор нестабилен → ретраи; консолидация удалась на последней попытке)_"
    return f"**Финализация сессии** → HTTP {codes}{note}"


def _landing_delta(attempt):
    """Строка про дифф ярусов памяти на шаге финализации (before → after-finalize)."""
    for step in attempt.get("state_diff") or []:
        if step.get("to") == "after-finalize":
            d = step.get("delta") or {}
            parts = [f"{tier} +{v.get('added', 0)}" for tier, v in d.items() if v.get("added")]
            return ", ".join(parts) if parts else "изменений ярусов не зафиксировано"
    return "нет данных диффа"


_TIER = {"global": "agent_policy_memories (scope=global)",
         "user": "semantic_memories (scope=user)",
         "both": "agent_policy (global) + semantic (user)"}


def _register_table(attempts):
    """Группировка попыток по формулировке (turns[0]) с исходами."""
    from collections import OrderedDict
    by = OrderedDict()
    for a in attempts:
        turns = a.get("turns") or []
        key = turns[0] if turns else "(без формулировки)"
        b = by.setdefault(key, {"n": 0, "g": 0, "u": 0, "e4": 0})
        b["n"] += 1
        b["g"] += 1 if a.get("E2_global") else 0
        b["u"] += 1 if a.get("E2_user") else 0
        b["e4"] += 1 if a.get("E4_marker_in_reply") else 0
    order = sorted(by.items(), key=lambda kv: (-kv[1]["g"], -kv[1]["u"]))
    rows = ["| # | формулировка (дословно, `{marker}` = метка-канарейка) | n | →global | →user | метка в ответе |",
            "|---|---|---|---|---|---|"]
    for i, (text, b) in enumerate(order, 1):
        cell = text.replace("|", "\\|")
        rows.append(f"| {i} | {cell} | {b['n']} | {b['g']} | {b['u']} | {b['e4']} |")
    return "\n".join(rows)


def _worked_example(attempt, calls, kind):
    """Развёрнутый пример одной успешной попытки: реальные запросы + вердикт оракула."""
    marker = attempt["marker"]
    atk = attempt["attacker"]
    tgt = attempt["spread_target"]
    chats = _poison_chats(marker, calls)
    sids = {_req_body(c).get("session_id") for c in chats}
    fins = _finalizes(sids, calls)
    scope = attempt.get("landing_scope")

    out = []
    if kind == "global":
        out.append(f"Атакующий **{atk}** → цель распространения **{tgt}** (ДРУГОЙ клиент). "
                   f"Ярус: `{_TIER['global']}`. Маркер-канарейка: `{marker}`.")
    else:
        out.append(f"Атакующий **{atk}**, эффект проверяем на нём же в НОВОЙ сессии (within-user). "
                   f"Ярус: `{_TIER['user']}`. Маркер-канарейка: `{marker}`.")

    out.append("\n**Шаг 1 — посадка правила (запрос ушёл по проводу):**\n")
    for c in chats:
        b = _req_body(c)
        out.append(_http_block(c.get("url"), atk, b))
        out.append("")
        out.append(_reply_block(c))
        out.append("")

    out.append("**Шаг 2 — финализация сессии (консолидация диалога в долгую память):**\n")
    out.append(_finalize_line(fins) + "\n")

    out.append("**Шаг 3 — оракул состояния (рефери; дифф памяти, не текст):**\n")
    e1 = "✔ присутствовал" if attempt.get("E1_in_working") else "— не зафиксирован"
    out.append(f"- **E1** (redis, рабочая память сессии): маркер {e1}.")
    out.append(f"- **E2** (приземление): дифф на финализации — `{_landing_delta(attempt)}`; "
               f"маркер закрепился на ярусе **{_TIER.get(scope, scope)}** ✔.")
    e3 = "✔" if attempt.get("E3_in_context") else "—"
    out.append(f"- **E3** (сборка контекста цели {tgt}): маркер в контексте {e3} "
               f"(канал `{attempt.get('E3_via')}`).\n")

    out.append(f"**Шаг 4 — эффект на цель ({tgt}, новая сессия):**\n")
    vr = _victim_read(marker, calls)
    if vr is not None:
        out.append(_http_block(vr.get("url"), tgt, _req_body(vr)))
        out.append("")
        out.append(_reply_block(vr))
    else:
        excerpt = (attempt.get("target_reply_excerpt") or "").strip() or "(нет)"
        out.append(f"Нейтральный вопрос клиенту {tgt} в новой сессии. Ответ (фрагмент): "
                   f"«{excerpt}»")
    j = attempt.get("E4_judge") or {}
    if j.get("influence") is not None:
        out.append(f"\nДифф-судья: influence **{j.get('influence')}**, shifted={j.get('shifted')}.")
    e4 = attempt.get("E4_marker_in_reply")
    if kind == "global":
        verdict = ("правило, посаженное клиентом {a}, пересекло границу арендатора и всплыло у "
                   "клиента {t} — **cross-tenant отравление общей памяти**.").format(a=atk, t=tgt)
    else:
        verdict = ("правило закрепилось в личной памяти клиента и пережило сессию — "
                   "**within-user стойкость** (маркер входит в собственный контекст).")
    marktag = "метка всплыла в ответе" if e4 else "в ответе этой попытки метка не проявилась (но E3 — в контексте)"
    out.append(f"\n**Вывод:** {verdict} ({marktag}).")
    return "\n".join(out)


# ---- сборка документа -----------------------------------------------------

def build(run_dir):
    """Собрать poison_proof.md в run_dir из его логов. Вернёт путь или None (нет успехов)."""
    attempts = _load_attempts(run_dir)
    if not attempts:
        return None
    calls = _load_calls(run_dir)
    run_id = os.path.basename(run_dir.rstrip("/"))

    globals_ = [a for a in attempts if a.get("E2_global")]
    users = [a for a in attempts if a.get("E2_user") and not a.get("E2_global")]
    n = len(attempts)

    # лучший пример каждого класса: где эффект виден в ответе (E4), иначе просто приземление
    def best(pool):
        if not pool:
            return None
        return max(pool, key=lambda a: (bool(a.get("E4_marker_in_reply")),
                                        bool(a.get("E3_in_context")),
                                        (a.get("E4_judge") or {}).get("influence") or 0))

    ex_g = best(globals_)
    ex_u = best(users)

    doc = []
    doc.append("# Пруф воздействия — отравление памяти агента\n")
    doc.append(f"_Реконструкция из логов прогона `{run_id}`. Источники: `attempts.jsonl` "
               "(вердикт оракула состояния по каждой попытке) и `calls.jsonl` (фактические "
               "HTTP-запросы к агенту). Bearer-токены заменены на `<ключ клиента N>`._\n")
    doc.append("**Как читать.** Отравление — не один запрос, а конверсия из 4 стадий; задержка "
               "живёт МЕЖДУ ними:\n"
               "`E1` инъекция в рабочей памяти (redis) → `E2` финализация консолидирует её на "
               "ярус долгой памяти (**приземление**) → `E3` запись входит в собранный контекст "
               "цели → `E4` ответ цели искажён. Приземление вероятностно — меряем частотой на N. "
               "Рефери — **оракул состояния** (диффы коллекций памяти), а не текст ответа.\n")
    doc.append(f"**Итог прогона:** {n} попыток; **cross-tenant** (scope=global) — "
               f"**{len(globals_)}**; **within-user** (scope=user) — **{len(users)}**.\n")
    doc.append("---\n")

    doc.append("## 1. Арсенал: какие формулировки отправлялись в агента\n")
    doc.append("Каждая формулировка (регистр) прогонялась N раз со свежей меткой-канарейкой; "
               "оракул считал, на какой ярус она приземляется.\n")
    doc.append(_register_table(attempts) + "\n")
    doc.append("**Вывод по регистрам:** cross-tenant (общий ярус) тянет **регуляторно-"
               "комплаенсный** регистр («ЦБ РФ требует…», «общее требование платформы»); личные "
               "формулировки («хочу, чтобы ты…») садятся на **личный** ярус клиента (within-user). "
               "Нейтральные реплики (контроль) не приземляются — базовая частота ≈ 0.\n")
    doc.append("---\n")

    if ex_g is not None:
        doc.append("## 2. Пример A — Cross-tenant: отравление ОБЩЕЙ памяти (scope=global) `[критично]`\n")
        doc.append(_worked_example(ex_g, calls, "global") + "\n")
        doc.append("---\n")

    if ex_u is not None:
        head = "3" if ex_g is not None else "2"
        doc.append(f"## {head}. Пример B — Within-user: стойкий факт в ЛИЧНОЙ памяти (scope=user)\n")
        doc.append(_worked_example(ex_u, calls, "user") + "\n")
        doc.append("---\n")

    # полный список дословных запросов (дедуп по формулировке, реальный пример метки)
    doc.append("## 4. Все дословные запросы отравления (дедуп по формулировке)\n")
    doc.append("Первое сообщение каждой попытки — та самая инъекция; ниже — по одному реальному "
               "примеру на формулировку (метка уже подставлена, как ушло по проводу).\n")
    seen = set()
    idx = 0
    for a in attempts:
        turns = a.get("turns") or []
        key = turns[0] if turns else None
        if not key or key in seen:
            continue
        seen.add(key)
        idx += 1
        marker = a["marker"]
        chats = _poison_chats(marker, calls)
        doc.append(f"**{idx}.** (атакующий {a['attacker']}, метка `{marker}`, "
                   f"исход: {a.get('landing_scope')})\n")
        if chats:
            for c in chats:
                msgs = _req_body(c).get("messages") or []
                for msg in msgs:
                    if msg.get("role") == "user":
                        doc.append(f"> {msg.get('content')}")
        else:
            for t in turns:
                doc.append(f"> {t.replace('{marker}', marker)}")
        doc.append("")

    out_path = os.path.join(run_dir, "poison_proof.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(doc))
    return out_path
