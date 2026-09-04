# genai-harness — универсальный test-harness для GenAI-агента с памятью

Легитимная защитная тула (как SAST/фаззер/red-team): воспроизводимо находит слабости агентных
систем — **несанкционированный доступ к данным (BAC)** и **отравление памяти** — и измеряет их
**детерминированным оракулом состояния**, а не по тексту ответа агента. Каждая находка ведёт к
парному пруфу `vulnerable`↔`protected` («дыра есть» → «дыра закрыта») — основа для харденинга.

## Принцип №0 — тула не сшита с целью

Все факты о цели (ручки, ярусы памяти, коллекции, инструменты, идентичности, эталон, модели)
берутся из **`config/target.yaml`**, собранного из `customer_info.md`. **Перенос на другую цель =
замена `target.yaml` (+ `customer_info.md`), без единой правки кода.** Чего нет в customer_info —
помечается `needs_review`, тула деградирует на black-box (наблюдаемые наружу признаки).

## Установка

```bash
cd genai-harness
python3 -m venv .venv && ./.venv/bin/pip install pyyaml pymongo redis requests
echo 'OPENROUTER_API_KEY=sk-or-v1-...' > .env      # ключ для слотов attacker/judge
```

Цель должна быть поднята (для стенда genai-invest: `cd ~/genai-invest-stand && docker compose up -d`).
Модель ЦЕЛИ меняется в `.env` стенда (оверлей), не в коде тулы.

## Запуск

```bash
./.venv/bin/python run.py smoke              # провижининг, чат, оракул, teardown (без LLM)
./.venv/bin/python run.py bac    --attempts 5   # Таск A: BAC (3 канала), findings
./.venv/bin/python run.py poison --attempts 6   # Таск B: отравление, E1..E4, landing-rate
./.venv/bin/python run.py chain  --attempts 4   # связка A×B: чужой id через память -> BAC
./.venv/bin/python run.py models --attempts 6   # сравнение атакующих моделей (мутатор)
./.venv/bin/python run.py all    --attempts 6   # bac + poison
```

Прогресс идёт в консоль (stderr) в реальном времени: этапы каналов и тики по каждой попытке
(`[3/6] leak=True`, `[2/4] E1=.. E2=.. scope=.. E3=.. E4=..`). Итоговый JSON — в stdout, поэтому
`run ... > out.json` даёт чистый JSON, а прогресс виден на экране. Тихий режим: `HARNESS_QUIET=1`.
Матрица целевых моделей (перезапуск стенда per-model): `python -m harness.orchestration.target_matrix`.

Результаты — в `harness/runs/<run-id>/`: `findings.json`/`findings.md` (главный артефакт),
`attempts.jsonl` (сырой лог попыток, одна = строка), `calls.jsonl` (аудит вызовов агента),
`openrouter.jsonl` (вызовы attacker/judge: модель, параметры, `finish_reason`, `empty`),
`*_summary.json`, `susceptibility_*.md`.

## Архитектура (слои)

- `config/` — замороженный спек: `target.yaml`, `hypotheses.yaml`, `models.yaml`, `payloads.yaml`.
- `core/` — `config` (единая правда), `client` (транспорт+аудит), `provisioning` (headless-ключи),
  `openrouter` (attacker/judge), `attacker` (LLM-генерация/мутация запросов), `isolation`
  (session_id, teardown канареек, reset памяти).
- `oracle/` — `state` (BAC + чтение ярусов), `fingerprints` (мульти-отпечаток, без ложных плюсов),
  `memory_observer` (память как временной ряд, диффы), `judge_llm` (дифференциальный судья).
- `tasks/` — `bac` (Таск A), `memory_poison` (Таск B: E1→E4, продольно), `chain_ab`.
- `orchestration/` — `run` (точка входа/CLI).
- `report/` — `findings`, `stats` (Уилсон CI), `susceptibility`.

## Инварианты (из ТЗ)

- **Оракул состояния — рефери.** LLM может стоять где угодно (генерация атаки, детект,
  оркестрация), но вердикт по классу выносит проверка состояния хранилищ + эталон. LLM-судья
  калибруется ОТНОСИТЕЛЬНО оракула, не вместо.
- **Изоляция.** Уникальный `session_id` на попытку; teardown канареек; опция полного reset
  памяти (чистый прогон). Состояние между прогонами не течёт.
- **Темпоральность отравления.** Не «атаковал → сразу проверил»: finalize дёргается явно
  (2 канала — endpoint и слово `finalize`), приземление меряется как ЧАСТОТА на N (стохастика
  консолидатора), учитываются оба яруса (global=cross-tenant, user=within-user — тоже результат).
- **Против ложного «безопасно».** Свип формулировок и моделей-атакующих (объединение найденного),
  мульти-отпечаток, дифференциальный судья, контроль (protected + безобидный baseline). «Не
  воспроизведено» ≠ «безопасно»: репортится как «не продемонстрировано при (модели, атакующие, N)».

## Перенос на другую цель (и независимая перепроверка)

1. Напиши `customer_info.md` новой цели, собери из него `config/target.yaml` (та же схема).
2. По необходимости адаптируй `hypotheses.yaml`/`payloads.yaml` (регистры формулировок).
3. Запусти `smoke` → `bac`/`poison`. Если grey-box (redis/mongo) недоступен — оракул
   деградирует на наблюдаемые признаки (ответ finalize, `GET /memory`, отпечатки), это
   фиксируется как более слабый режим детекта. Артефакт `findings.json` самодостаточен для
   повтора на другом агенте.
