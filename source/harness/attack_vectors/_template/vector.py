"""ШАБЛОН вектора атаки. Скопируй папку _template/ в attack_vectors/<name>/ и заполни.

Полная инструкция автора: docs/ATTACK_VECTORS.md. Кратко: реализуй run() и findings();
вердикт бери у оракула (oracle/state.py), не по тексту; ноль литералов цели (всё через ctx.cfg);
каждую попытку оборачивай в attempt_guard (failsafe); из run НЕ бросай — верни частичный summary.
Папка _template/ начинается с '_' -> discovery её пропускает (это не боевой вектор).
"""

from ...report import findings as F                  # фабрика находок
from ...report.stats import summarize_rate           # доля успеха + Wilson-CI
from ...oracle import state                          # детерминированный оракул (вердикт)
from ..base import AttackVector, attempt_guard        # контракт + failsafe попытки


class TemplateVector(AttackVector):
    # --- метаданные (заполни) -------------------------------------------------
    name = ""                                # оставь пустым -> возьмётся имя папки [a-z0-9_]
    title = "TODO: человекочитаемое имя вектора"
    mutates_state = False                     # True, если пишешь в память/политику стенда
    taxonomy = {"owasp_asi": "TODO", "owasp_llm": "TODO"}
    requirements = ()                         # напр. ("greybox",) — код-гейт применимости
    hypotheses = ()                           # напр. ("H1-...",) — что покрываешь (справочно)

    # --- применимость (опц.) --------------------------------------------------
    def applicable(self, ctx):
        # верни False, если цель не подходит (вектор аккуратно пропустят)
        return True

    # --- сама атака -----------------------------------------------------------
    def run(self, ctx):
        cfg = ctx.cfg
        attempts = int(self.params.get("attempts", 5))
        hits = 0
        for i in range(attempts):
            with attempt_guard(ctx.run, label=f"{self.name}#{i}"):   # попытка не валит вектор
                # TODO: выполни одну попытку. Примеры доступного:
                #   client = ctx.client(); r = client.chat(key, text, session_id=...)
                #   verdict = state.served_cross_cus(a, v, cfg.mode("vulnerable"), cfg)
                # Логируй попытку (под перепроверку):
                ctx.run.attempt({"vector": self.name, "seq": i, "user_text": "TODO", "ok": False})
                # if verdict: hits += 1
                pass
        # НЕ бросай наружу: верни частичный результат
        return {"target": cfg.target["target"]["name"], "greybox": True,
                "attempts": attempts, "hits": hits}

    # --- находки (вердикт -> отчёт) -------------------------------------------
    def findings(self, summary, ctx):
        rate = summarize_rate(summary["hits"], summary["attempts"])
        return [F.finding(
            f"F-{self.name.upper()}-1", self.name, self.title,
            {"channel": "TODO", "call": "TODO: как повторить руками"},   # reproduction
            "TODO: чем подтверждено (оракул/отпечаток)",                  # detection
            rate,                                                        # доля + CI (или None)
            "high" if rate["nonzero"] else "info",
            status="demonstrated" if rate["nonzero"] else "not-demonstrated",
            notes="TODO")]
