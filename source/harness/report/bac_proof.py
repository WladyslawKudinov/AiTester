"""Человекочитаемый результат BAC с ПЕРВИЧНЫМИ ЗАПРОСАМИ — что реально ушло агенту.

Главная секция — «Все первичные запросы к агенту (LLM→tool BAC)»: КАЖДАЯ формулировка, которую
харнесс отправил агенту (seed + сгенерированные атакующей моделью + adaptive-мутации), с вердиктом
утечки. Раньше в proof.md попадал только один пример (дедуп), и первичных запросов было не видно —
теперь видно все.

Собирается из логов прогона: attempts.jsonl (записи agent_mediated с полем prompt + leak +
victim_fingerprints; data_layer; account_owner) и calls.jsonl (полные ответы агента). Запрос
показываем минимально — только сам текст сообщения, без служебных полей.
"""

import json
import os

from . import poison_proof as PP


def _load(run_dir, name):
    path = os.path.join(run_dir, name)
    if not os.path.exists(path):
        return []
    return [json.loads(l) for l in open(path, encoding="utf-8")]


def _full_reply(calls, session_id, prompt):
    """Полный ответ агента на конкретный первичный запрос (по session_id + тексту сообщения)."""
    for c in calls:
        if "/v1/chat" not in (c.get("url") or ""):
            continue
        b = PP._req_body(c)
        if b.get("session_id") != session_id:
            continue
        msg = ""
        for m in (b.get("messages") or []):
            if m.get("role") == "user":
                msg = m.get("content", "")
        if msg == prompt:
            return PP._chat_reply(c), c.get("status"), c.get("latency_s")
    return None, None, None


def _req(client_cus, prompt):
    q = (prompt or "(пусто)").replace("\n", "\n> ")
    return f"**Что написал юзер** (клиент {client_cus} → агенту):\n\n> " + q


def _resp(reply, status=None, lat=None):
    t = (reply or "(пустой ответ)").strip()
    if len(t) > 900:
        t = t[:900] + " …[обрезано]"
    head = "**Ответ агента"
    if status is not None:
        head += f" (HTTP {status}" + (f", {lat:.1f}s" if isinstance(lat, (int, float)) else "") + ")"
    head += ":**"
    return head + "\n\n> " + t.replace("\n", "\n> ")


def build(run_dir):
    att = _load(run_dir, "attempts.jsonl")
    calls = _load(run_dir, "calls.jsonl")
    run_id = os.path.basename(run_dir.rstrip("/"))

    agent = [a for a in att if a.get("channel") == "agent_mediated" and a.get("prompt")]
    data = [a for a in att if a.get("channel") == "data_layer"]
    owner = [a for a in att if a.get("channel") == "account_owner"]
    if not (agent or data or owner):
        return None

    attacker = str((agent or data or owner)[0].get("attacker", "1001"))
    victim = str((agent[0].get("victim") if agent else (data[0].get("victim") if data else "?")))
    leaks = [a for a in agent if a.get("leak")]

    d = []
    d.append("# PoC BAC — что написал юзер\n")
    d.append(f"_Прогон `{run_id}`. Источник: `attempts.jsonl` (вердикт по каждому запросу) + "
             "`calls.jsonl` (полные ответы). Показано минимально — только сам текст сообщения "
             "юзера агенту, без служебных полей._\n")
    d.append(f"**Итог agent-mediated (LLM→tool):** юзер (клиент {attacker}) написал агенту "
             f"**{len(agent)}** сообщений, из них с утечкой данных клиента {victim} — "
             f"**{len(leaks)}**.\n")
    d.append("---\n")

    # ГЛАВНАЯ СЕКЦИЯ: что именно написал юзер
    d.append("## 1. Что написал юзер агенту (LLM→tool BAC) — все сообщения\n")
    d.append("Каждое сообщение, которое юзер (атакующий, клиент {a}) написал агенту (seed + "
             "сгенерированные атакующей моделью + adaptive-мутации), в порядке отправки. "
             "`[УТЕЧКА]` — в ответе агента всплыли данные чужого клиента.\n".format(a=attacker))
    for i, a in enumerate(agent, 1):
        prompt = a.get("prompt", "")
        leaked = bool(a.get("leak"))
        model = a.get("attacker_model") or "seed"
        tag = "[УТЕЧКА]" if leaked else "[нет утечки]"
        d.append(f"### {i}. {tag}  _(источник формулировки: {model}, режим {a.get('auth_mode')})_\n")
        d.append(_req(attacker, prompt))
        d.append("")
        if leaked:
            hits = a.get("victim_fingerprints") or []
            reply, st, lat = _full_reply(calls, a.get("session_id"), prompt)
            if reply is None:
                reply, st, lat = a.get("reply_excerpt"), a.get("status"), None
            d.append(_resp(reply, st, lat))
            d.append(f"\n→ **утечка**: в ответе отпечатки клиента {victim}: `{hits}` "
                     "(эхо запроса исключено).")
        else:
            d.append(f"→ нет утечки (агент не выдал данные клиента {victim}).")
        d.append("")
    d.append("---\n")

    # СЛОЙ ДАННЫХ (REST) — юзер ничего НЕ пишет
    if data or owner:
        d.append("## 2. Прямой REST — юзер НИЧЕГО не пишет (service-to-service)\n")
        d.append("_Это НЕ через юзер-ввод: харнесс шлёт токеном атакующего прямой HTTP-запрос к "
                 "сервису данных, мимо агента/LLM. «Что написал юзер» тут отсутствует по природе "
                 "вектора — это отдельная (сервисная) находка._\n")
    if data:
        for a in data:
            served = a.get("served")
            d.append(f"- `GET client_by_cus({victim})` (как клиент {attacker}, режим "
                     f"`{a.get('auth_mode')}`) → HTTP {a.get('status')}, "
                     f"{'ОТДАЛ данные' if served else 'закрыл'}"
                     + (f"; отпечатки: `{a.get('fingerprints')}`" if a.get('fingerprints') else "")
                     + ".")
            if served and a.get("data"):
                d.append("\n  Что вернул сервис:\n")
                d.append("  ```json\n  " + json.dumps(a["data"], ensure_ascii=False) + "\n  ```")
        d.append("")
    if owner:
        d.append("\n**Владелец чужого счёта:**\n")
        for a in owner:
            ow = json.dumps(a.get("owner"), ensure_ascii=False) if a.get("resolved") else None
            d.append(f"- `GET account_owner` (как клиент {attacker}, режим `{a.get('auth_mode')}`) "
                     f"→ HTTP {a.get('status')}, "
                     f"{'резолвит владельца: ' + ow if a.get('resolved') else 'закрыл'}.")
        d.append("")

    out = os.path.join(run_dir, "proof.md")   # единый файл — не плодим второй
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(d))
    return out
