# AI Test CUI — харнесс тестирования безопасности агентов с памятью

Конфиг-driven инструмент: детерминированный оракул состояния — рефери, LLM только генерит/мутирует
атаки и мягко судит. Перенос на другую цель = замена `source/harness/config/target.yaml`.

## Раскладка

| папка | что |
|---|---|
| `source/` | код — пакет `harness/` (core, oracle, tasks, orchestration, report, recon, config, fixtures) |
| `docs/` | документация: архитектура, контекст, находки, ТЗ, PDF, `customer_info.md` |
| `output/` | результаты прогонов: `runs/<id>/`, сводный `PROOF.md` — не в git |

`.env` (ключ OpenRouter) и `source/harness/fixtures/keys.json` (кэш ключей) — вне git.

## Запуск (из корня проекта)

```bash
./.venv/bin/python run.py smoke                 # без LLM: провижининг, чат, оракул, teardown
./.venv/bin/python run.py bac    --attempts 5   # Таск A: BAC (3 канала)
./.venv/bin/python run.py poison --attempts 6   # Таск B: отравление памяти E1..E4
./.venv/bin/python run.py poison-proof [--run ID] # человекочитаемый пруф отравления из логов
./.venv/bin/python run.py llm-repro             # ручной повтор LLM-находок (адрес из конфига) + лог
./.venv/bin/python run.py chain  --attempts 4   # связка A×B: чужой id через память -> BAC
./.venv/bin/python run.py models --attempts 6   # сравнение атакующих моделей (мутатор)
./.venv/bin/python run.py all    --attempts 6   # bac + poison
./.venv/bin/python run.py mem  [--marker X]     # проверка ярусов памяти (policy=cross-tenant)
./.venv/bin/python run.py repro                 # готовые curl-PoC на каждую находку
```

Прогресс идёт в консоль (stderr) вживую; итог JSON — в stdout. Тихий режим: `HARNESS_QUIET=1`.
Матрица целевых моделей (перезапуск стенда per-model):
`cd source && ../.venv/bin/python -m harness.orchestration.target_matrix`.

## Где результаты

`output/runs/<run-id>/`: `findings.md`/`findings.json` (главный артефакт), `proof.md` (PoC успешных
атак, воспроизводимо руками), `poison_proof.md` (пруф отравления: дословные запросы из `calls.jsonl`
+ вердикт оракула по стадиям E1..E4), `attempts.jsonl`, `calls.jsonl`, `openrouter.jsonl`,
`coverage.md`, `*_summary.json`. Сводный PoC по таскам — `output/PROOF.md`; последний пруф
отравления — `output/POISON_PROOF.md` (обновляется командами `poison` и `poison-proof`);
ручное воспроизведение LLM-находок (agent-BAC + отравление; шаги по адресу из конфига + лог
запросов/ответов) — `output/LLM_FINDINGS_REPRO.md` (команда `llm-repro`).
