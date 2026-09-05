"""Stub-вектор: ничего не атакует, просто прогоняет архитектуру end-to-end (без стенда).

Проверяет: discovery (ноль регистрации) -> CLI-грамматику (a-stub, stub--key=val) -> драйвер
(applicable/run/findings) -> стандартный отчёт report__stub.{json,md}. Референс минимального
вектора для автора. mutates_state=False -> lease/reset не берётся (безопасно гонять где угодно).
"""

from ...report import findings as F
from ..base import AttackVector, attempt_guard


class StubVector(AttackVector):
    name = "stub"
    title = "Проверка архитектуры (stub)"
    mutates_state = False
    taxonomy = {"owasp_asi": "N/A (self-test)", "owasp_llm": "N/A (self-test)"}
    requirements = ()          # ничего не требует от цели — гоняется всегда
    hypotheses = ()

    def applicable(self, ctx):
        return True

    def run(self, ctx):
        msg = self.params.get("message", "stub ok")
        reps = int(self.params.get("reps", 2))
        print(f"[stub] message={msg!r} reps={reps} params={self.params}")
        ok = 0
        for i in range(reps):
            # КАЖДУЮ попытку оборачиваем: падение одной итерации не роняет вектор (failsafe).
            with attempt_guard(ctx.run, label=f"stub#{i}"):
                ctx.run.attempt({"vector": "stub", "seq": i, "user_text": msg, "ok": True})
                ok += 1
        return {"vector": "stub", "message": msg, "reps": reps, "ok_attempts": ok, "ok": ok > 0,
                "target": ctx.cfg.target["target"]["name"], "greybox": True}

    def findings(self, summary, ctx):
        return [F.finding(
            "F-STUB-OK", "stub", "Каркас attack_vectors работает end-to-end",
            {"channel": "self-test (без цели)", "message": summary["message"],
             "reps": summary["reps"], "call": "discover -> a-stub -> run -> findings -> report"},
            f"stub выполнился: {summary['message']} ×{summary['reps']}",
            None, "info",
            status="demonstrated" if summary.get("ok") else "not-demonstrated",
            notes="Диагностический вектор: подтверждает discovery/грамматику/драйвер/отчёт.")]
