"""Единый писатель отчётов НА ВЕКТОР (стандарт для сборки ядром-LLM).

Каждый вектор кладёт в папку прогона два файла с именем, кодирующим вектор:
  report__<name>.json  — строгая схема (attack_vectors.base.standard_report), машинно/для ядра.
  report__<name>.md    — человекочитаемо, единые заголовки; тело — proof вектора (что написал
                         юзер), если он есть, иначе рендер из находок.
Ядро-LLM читает все report__*.json, группирует по taxonomy/severity и собирает сводку.
"""

import os

from ..attack_vectors.base import standard_report


def write(run, vector, summary, findings, cfg):
    """-> (json_path, md_path). Пишет report__<name>.json и report__<name>.md в run.dir."""
    doc = standard_report(vector, summary, findings, cfg, run)
    json_path = run.write_json(f"report__{vector.name}.json", doc)
    md_path = run.write_text(f"report__{vector.name}.md", _md(vector, doc, run))
    return json_path, md_path


def _md(vector, doc, run):
    a = doc["attempts_summary"]
    lines = [f"# Отчёт вектора: {doc['title']}  (`{doc['vector']}`)", "",
             f"Цель: {doc['target']}  ·  прогон: {doc['run_id']}  ·  {doc['generated']}",
             f"Меняет стейт стенда: {'да' if doc['mutates_state'] else 'нет'}  ·  "
             f"находок: {a['findings']} (воспроизведено: {a['demonstrated']})", ""]
    tx = doc.get("taxonomy") or {}
    if tx:
        lines += [f"Таксономия: OWASP ASI — {tx.get('owasp_asi', '-')}; "
                  f"OWASP LLM — {tx.get('owasp_llm', '-')}", ""]
    lines.append(f"## Находки ({a['findings']})\n")
    for f in doc["findings"]:
        lines += _md_finding(f)

    proof = None
    try:
        proof = vector.proof(run.dir)
    except Exception:
        proof = None
    if proof and os.path.exists(proof):
        lines += ["## Что написал юзер / пруф воздействия", "",
                  open(proof, encoding="utf-8").read()]
    return "\n".join(lines)


def _md_finding(f):
    out = [f"### {f['finding_id']} — {f['goal']}  `[{f['severity']}]`  · итог: {f['outcome']}", "",
           f"- **тип:** {f['type']}"]
    tx = f.get("taxonomy") or {}
    if tx.get("owasp_asi") or tx.get("owasp_llm"):
        out.append(f"- **таксономия:** ASI {tx.get('owasp_asi', '-')} · LLM {tx.get('owasp_llm', '-')}")
    for k, v in (f.get("repro") or {}).items():
        out.append(f"- **{k}:** {v}")
    out.append(f"- **детект:** {f.get('detector')}")
    so = f.get("state_oracle") or {}
    out.append(f"- **state-оракул:** {'да' if so.get('used') else 'нет (behavioral)'}")
    r = f.get("rate")
    if r:
        out.append(f"- **доля успеха:** {r['successes']}/{r['n']} = {r['rate']} "
                   f"(95% CI {r['ci95'][0]}–{r['ci95'][1]}){' · НЕНУЛЕВОЙ' if r.get('nonzero') else ''}")
    else:
        out.append("- **метод:** детерминированный (оракул состояния), доля не применяется")
    if f.get("reason"):
        out.append(f"- **заметки:** {f['reason']}")
    out.append("")
    return out
