"""Сборка главного артефакта: findings.json (+ findings.md).

Каждая находка самодостаточна для независимой перепроверки на ДРУГОМ агенте: репродукция в
общем словаре (канал / роль инструмента / ярус памяти) + конкретные параметры этой цели.
Отрицательный результат репортится как «не продемонстрировано при условиях», не как «безопасно».
"""

import json
import time


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Маппинг класса находки на отраслевую таксономию (OWASP Agentic Security Initiative + LLM Top-10).
# Даёт находкам «язык индустрии» и переносится между целями. Авто по классу, можно переопределить.
_TAXONOMY = {
    "bac":           {"owasp_asi": "Privilege/Identity Abuse (BOLA)", "owasp_llm": "LLM06 Excessive Agency"},
    "poison-global": {"owasp_asi": "Memory Poisoning (cross-tenant)", "owasp_llm": "LLM01 Prompt Injection"},
    "within-user":   {"owasp_asi": "Memory Poisoning (within-user)",  "owasp_llm": "LLM01 Prompt Injection"},
    "chain-AxB":     {"owasp_asi": "Tool Misuse via poisoned memory", "owasp_llm": "LLM06 Excessive Agency"},
}


def finding(fid, cls, title, reproduction, detection, rate, severity,
            status="demonstrated", notes=None, taxonomy=None):
    """Одна находка. rate = dict из stats.summarize_rate или None (для детерминированных).
    taxonomy — {owasp_asi, owasp_llm, cvss?}; по умолчанию авто из класса (_TAXONOMY)."""
    return {
        "id": fid,
        "class": cls,                       # bac | poison-global | within-user | chain-AxB
        "title": title,
        "status": status,                   # demonstrated | not-demonstrated
        "severity": severity,
        "reproduction": reproduction,       # общий словарь + конкретные параметры
        "detection": detection,             # чем подтверждён (состояние/отпечаток)
        "success": rate,                    # доля на N + CI (или null для детерминированного)
        "taxonomy": taxonomy or _TAXONOMY.get(cls, {}),   # отраслевая таксономия (OWASP ASI/LLM)
        "notes": notes or "",
    }


def write(run, findings, meta=None):
    """Записать findings.json и findings.md в папку прогона."""
    findings = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9),
                                               0 if f["status"] == "demonstrated" else 1))
    doc = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
           "run_id": run.run_id,
           "target": (meta or {}).get("target"),
           "models": (meta or {}).get("models"),
           "count": len(findings),
           "findings": findings}
    run.write_json("findings.json", doc)
    run.write_text("findings.md", _md(doc))
    return doc


def _md(doc):
    lines = [f"# Findings — {doc['run_id']}", "",
             f"Сгенерировано: {doc['generated']}  ·  цель: {doc.get('target')}  ·  находок: {doc['count']}",
             ""]
    demonstrated = [f for f in doc["findings"] if f["status"] == "demonstrated"]
    negative = [f for f in doc["findings"] if f["status"] != "demonstrated"]

    lines.append(f"## Воспроизведено ({len(demonstrated)})\n")
    for f in demonstrated:
        lines += _md_finding(f)
    if negative:
        lines.append(f"## Не продемонстрировано при данных условиях ({len(negative)})\n")
        lines.append("> Это НЕ «безопасно»: класс не воспроизведён при указанных моделях/атакующих/N.\n")
        for f in negative:
            lines += _md_finding(f)
    return "\n".join(lines)


def _md_finding(f):
    out = [f"### {f['id']} — {f['title']}  `[{f['severity']}]`", ""]
    out.append(f"- **Класс:** {f['class']}")
    tx = f.get("taxonomy") or {}
    tx_parts = []
    if tx.get("owasp_asi"):
        tx_parts.append(f"OWASP ASI: {tx['owasp_asi']}")
    if tx.get("owasp_llm"):
        tx_parts.append(f"OWASP LLM: {tx['owasp_llm']}")
    if tx.get("cvss"):
        tx_parts.append(f"CVSS: {tx['cvss']}")
    if tx_parts:
        out.append(f"- **Таксономия:** {'; '.join(tx_parts)}")
    rep = f["reproduction"]
    for k, v in rep.items():
        out.append(f"- **{k}:** {v}")
    out.append(f"- **Детект:** {f['detection']}")
    if f.get("success"):
        s = f["success"]
        out.append(f"- **Доля успеха:** {s['successes']}/{s['n']} = {s['rate']} "
                   f"(95% CI {s['ci95'][0]}–{s['ci95'][1]}){' · НЕНУЛЕВОЙ' if s.get('nonzero') else ''}")
    else:
        out.append("- **Метод:** детерминированный (оракул состояния), доля не применяется")
    if f.get("notes"):
        out.append(f"- **Заметки:** {f['notes']}")
    out.append("")
    return out
