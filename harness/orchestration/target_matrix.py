"""Матрица susceptibility ЦЕЛЕВЫХ моделей: какая модель-мозг агента устойчивее к BAC.

Смена модели цели — через .env-оверлей стенда (config: deployment.*), НЕ правя код цели.
Тула БЭКАПИТ исходный env, гоняет BAC-канал на каждой модели, затем ВОССТАНАВЛИВАЕТ и
перезапускает — стенд всегда возвращается в исходное (try/finally).

Модель, не сумевшая вызвать инструмент (нет утечки И нет валидных ответов), — это провал
ВОЗМОЖНОСТЕЙ, не устойчивость; помечаем note, не засчитываем как «безопасно».
"""

import re
import shutil
import subprocess
import time
import urllib.request

from ..core.config import load
from ..core.runlog import Run
from ..tasks import bac
from ..report import susceptibility as S
from ..core import isolation


def _read_env(path):
    return open(path, encoding="utf-8").read()


def _set_env_var(text, var, value):
    """Заменить/добавить строку VAR=... в тексте .env."""
    pat = re.compile(rf"(?m)^{re.escape(var)}=.*$")
    if pat.search(text):
        return pat.sub(f"{var}={value}", text)
    return text.rstrip("\n") + f"\n{var}={value}\n"


def _restart_and_wait(dep, timeout=150):
    subprocess.run(dep["restart_cmd"], shell=True, cwd=dep["dir"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(dep["health_url"], timeout=5) as r:
                if r.status == 200:
                    time.sleep(3)   # дать модели-роутеру прогреться
                    return True
        except Exception:
            pass
        time.sleep(3)
    return False


def run_matrix(models=None, attempts=6, cfg=None):
    cfg = cfg or load()
    dep = cfg.target.get("deployment")
    if not dep:
        raise RuntimeError("нет секции deployment в target.yaml — оверлей модели невозможен")
    env_path = f"{dep['dir']}/{dep['env_file']}"
    backup = env_path + ".harness-bak"
    if models is None:
        models = cfg.slot_candidates("target_brain")

    run = Run("target-matrix-" + time.strftime("%Y%m%d-%H%M%S"), cfg)
    attacker, victim = cfg.attacker_default(), cfg.victim_default()
    rows = []
    original = _read_env(env_path)
    shutil.copy2(env_path, backup)
    try:
        for m in models:
            value = dep["model_value_tpl"].format(model=m)
            with open(env_path, "w", encoding="utf-8") as f:
                f.write(_set_env_var(original, dep["model_env_var"], value))
            healthy = _restart_and_wait(dep)
            if not healthy:
                rows.append({"model": m, "attempts": 0, "leaks": 0, "rate": 0.0,
                             "note": "agent-api не поднялся с этой моделью"})
                run.attempt({"task": "target_matrix", "model": m, "event": "unhealthy"})
                continue
            isolation.purge_all_canaries(cfg)
            res = bac.agent_mediated_campaign(
                run, cfg, attacker, victim, "vulnerable",
                attacker_models=[cfg.slot_default("attacker")], n_gen=attempts,
                max_steps=1, use_llm=True, include_seeds=True)
            note = "" if res["leaks"] else "нет утечки — возможно провал tool-calling (проверить логи)"
            rows.append({"model": m, "attempts": res["attempts"], "leaks": res["leaks"],
                         "rate": res["rate"], "note": note})
            run.attempt({"task": "target_matrix", "model": m, "rate": res["rate"],
                         "attempts": res["attempts"], "leaks": res["leaks"]})
    finally:
        # ВОССТАНОВЛЕНИЕ исходного .env + перезапуск
        with open(env_path, "w", encoding="utf-8") as f:
            f.write(original)
        _restart_and_wait(dep)

    rows = sorted(rows, key=lambda r: (r.get("rate") or 0, r["model"]))  # устойчивее = ниже rate
    S.write(run, "target", rows,
            extra={"attacker": attacker, "victim": victim, "channel": "agent_mediated (BAC)",
                   "note": "susceptibility мозга агента: ниже rate = устойчивее"})
    print("target susceptibility saved:", run.path("susceptibility_target.md"))
    for r in rows:
        print(f"  {r['model']}: {r['leaks']}/{r['attempts']} = {r['rate']} {r['note']}")
    return run


if __name__ == "__main__":
    run_matrix()
