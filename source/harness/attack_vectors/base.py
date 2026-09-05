"""Контракт вектора атаки + общий контекст + стандарт отчёта.

Вектор = самодостаточная папка attack_vectors/<name>/ с vector.py (подкласс AttackVector),
README.md и params.yaml. Discovery (registry.py) находит класс ИНТРОСПЕКЦИЕЙ — регистрировать
нигде не надо (ноль регистрации). Ядро (orchestration/run.py) гоняет вектор единым циклом:

    applicable(ctx) -> [stand_lease если mutates_state] -> setup -> run(ctx) -> findings(summary,ctx)
    -> report_std пишет report__<name>.{json,md} -> teardown

Вся цель/сервисы приходят в ctx (никаких глобалов): перенос тулы на другой стенд = замена
config/target.yaml, ни строки кода. Судью в отдельный ABC НЕ выносим — оракул общий и
детерминированный (наше преимущество), вектор зовёт его из ctx/oracle напрямую.
"""

import contextlib
import time
from dataclasses import dataclass, field
from typing import Any


# ── общий контекст: драйвер собирает и инъектирует в вектор ────────────────────
@dataclass
class VectorContext:
    run: Any                                      # runlog.Run — папка прогона + attempts.jsonl
    cfg: Any                                      # config.Config — единая правда о цели
    params: dict = field(default_factory=dict)    # параметры ЭТОЙ атаки (после precedence)
    _client: Any = None
    _attacker: Any = None
    _judge: Any = None

    # ленивые сервисы — нужны нативным векторам; мигрированные строят своё внутри run_mvp
    def client(self):
        if self._client is None:
            from ..core.client import AgentClient
            self._client = AgentClient(self.run.dir, self.cfg)
        return self._client

    def attacker(self):
        if self._attacker is None:
            from ..core.attacker import Attacker
            self._attacker = Attacker(self.run.dir, self.cfg)
        return self._attacker

    def judge(self):
        if self._judge is None:
            from ..oracle.judge_llm import Judge
            self._judge = Judge(self.run.dir, self.cfg)
        return self._judge


@contextlib.contextmanager
def attempt_guard(run=None, label="attempt", reraise=False):
    """Failsafe одной ПОПЫТКИ: исключение внутри не роняет вектор (а значит и оркестратор).
    Оборачивай КАЖДУЮ попытку в цикле run(): падение одной итерации не должно рвать остальные.
    Ошибка логируется строкой в attempts.jsonl. reraise=True — только для отладки."""
    try:
        yield
    except Exception as e:                        # noqa: BLE001 — намеренно широкий перехват
        if run is not None:
            try:
                run.attempt({"error": f"{type(e).__name__}: {str(e)[:200]}", "label": label})
            except Exception:
                pass
        if reraise:
            raise


# ── контракт вектора ──────────────────────────────────────────────────────────
class AttackVector:
    """Базовый класс атаки. Автор наследуется, объявляет метаданные класса и реализует
    run()/findings(); остальное опционально. Имя папки == идентификатор вектора (== self.name)."""

    # метаданные класса (переопределяет автор) --------------------------------
    name: str = ""                 # == имя папки; discovery проставит, если пусто
    title: str = ""                # человекочитаемое имя вектора
    mutates_state: bool = False    # меняет персистентный стейт стенда -> нужны lease + reset
    taxonomy: dict = {}            # {owasp_asi, owasp_llm} для находок вектора
    requirements: tuple = ()       # Тир-A код-гейт возможностей цели (greybox/multi_turn/...)
    hypotheses: tuple = ()         # какие H-id из hypotheses.yaml покрывает
    doc_uri: str = "README.md"     # дока рядом с вектором

    # дефолты параметров: registry подгружает из params.yaml в _param_defaults
    _param_defaults: dict = {}

    def __init__(self, params=None):
        self.params = dict(self._param_defaults or {})
        if params:
            self.params.update(params)

    @classmethod
    def param_schema(cls):
        """Схема параметров (из params.yaml): {key: {type,default,required,options?,description}}.
        registry кладёт в _param_schema; пусто, если params.yaml нет."""
        return getattr(cls, "_param_schema", {}) or {}

    # жизненный цикл ----------------------------------------------------------
    def applicable(self, ctx) -> bool:
        """Пригоден ли вектор к текущей цели (Тир-A гейт). По умолчанию — да."""
        return True

    def setup(self, ctx):
        pass

    def run(self, ctx) -> dict:
        """Выполнить атаку, вернуть summary (dict, пишется в <name>_summary.json)."""
        raise NotImplementedError

    def findings(self, summary, ctx) -> list:
        """Превратить summary в список находок (report.findings.finding(...))."""
        return []

    def teardown(self, ctx):
        pass

    def proof(self, run_dir):
        """Опц.: путь к собранному человекочитаемому proof.md (реюз bac_proof/poison_proof).
        Если None — report_std сам отрендерит MD из находок."""
        return None


# ── стандарт отчёта: суперсет полей 5 тулов, чтобы ядро-LLM собирало сводку ─────
# Порядок и имена совпадают с garak/pyrit/promptfoo/deepteam -> совместимо для агрегации.
_OUTCOME = {"demonstrated": "success", "not-demonstrated": "failure",
            "error": "error", "undetermined": "undetermined"}


def standard_finding(f, vector, summary):
    """Внутренняя находка (findings.finding) -> стандартная запись отчёта (строгая схема)."""
    rate = f.get("success")
    status = f.get("status")
    demonstrated = status == "demonstrated"
    outcome = _OUTCOME.get(status, "failure")     # success|failure|undetermined|error (pyrit-стиль)
    greybox = bool(summary.get("greybox", True)) if isinstance(summary, dict) else True
    detection = f.get("detection")
    return {
        # identity
        "finding_id": f.get("id"),
        "seq": None,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        # attack
        "vector": getattr(vector, "name", ""),
        "type": f.get("class"),
        "params": dict(getattr(vector, "params", {}) or {}),
        "goal": f.get("title"),
        # target
        "target_id": (summary.get("target") if isinstance(summary, dict) else None),
        "session_id": (summary.get("session_id") if isinstance(summary, dict) else None),
        # io (полный I/O — в report__<name>.md / attempts.jsonl; тут репро-словарь)
        "repro": f.get("reproduction"),
        # verdict
        "outcome": outcome,                        # success|failure|undetermined|error (pyrit-стиль)
        "score": (rate.get("rate") if rate else (1.0 if demonstrated else 0.0)),
        "passed": demonstrated,
        "rate": rate,                                          # {successes,n,rate,ci95,nonzero} | null
        # classification
        "severity": f.get("severity"),
        "taxonomy": f.get("taxonomy") or {},
        "risk_category": (f.get("taxonomy") or {}).get("owasp_asi"),
        # evidence
        "detector": detection,
        "reason": f.get("notes"),
        "state_oracle": {"used": greybox, "evidence": detection},   # НАШ дифференциатор
        # metrics
        "executed_turns": (summary.get("executed_turns") if isinstance(summary, dict) else None),
    }


def standard_report(vector, summary, findings, cfg, run):
    """Строгая схема report__<name>.json: шапка + стандартные находки + сводка попыток."""
    std = [standard_finding(f, vector, summary) for f in findings]
    demonstrated = sum(1 for f in std if f["passed"])
    return {
        "schema": "attack_vector_report/1",
        "vector": getattr(vector, "name", ""),
        "title": getattr(vector, "title", "") or getattr(vector, "name", ""),
        "target": cfg.target["target"]["name"],
        "run_id": run.run_id,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "mutates_state": bool(getattr(vector, "mutates_state", False)),
        "taxonomy": getattr(vector, "taxonomy", {}) or {},
        "params": dict(getattr(vector, "params", {}) or {}),
        "findings": std,
        "attempts_summary": {"findings": len(std), "demonstrated": demonstrated},
        "meta": {"hypotheses": list(getattr(vector, "hypotheses", ()) or ())},
    }
