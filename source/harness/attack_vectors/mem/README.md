# Вектор `mem` — отравление многоярусной памяти (E1..E4)

Внедряет через диалог факт/инструкцию (маркер-слово), триггерит консолидацию (`finalize`) и мерит,
куда он приземлился.

## Как это работает
- **E1** рабочая память (redis) до финализации; **E2** приземление на ярус (mongo policy/semantic);
  **E3** попадание в контекст жертвы (тем же лимитом, что система); **E4** всплытие в ответе.
- **cross-tenant** (`policy`, scope=global) → critical; **within-user** (`semantic`, scope=user) →
  high. Вердикт — дифф ярусов (grey-box). Меряем долю над **base_rate** + Wilson-CI.
- **Black-box**: нет mongo/redis → behavioral-оракул (метка в ответе новой сессии + rubric), находки
  помечаются ниже доверием (`F-POISON-BEHAVIORAL`).

State-меняющий (`mutates_state=True`): драйвер берёт lease; `run_mvp` делает точечную чистку канареек
(полный вайп — только `reset.full_wipe` в конфиге). Маркеры — обиходные слова (`fresh_marker`).

## Конфиг
`config/target.yaml`: storage (mongo коллекции/лимиты, redis), identities, finalize_triggers;
`config/payloads.yaml`: `memory_poisoning.<register>`. Ноль литералов.

## Параметры
См. `params.yaml`. Пример: `run.py a-mem mem--attempts=6 mem--registers=compliance`.

## Запуск
```
python -m harness.orchestration.run a-mem
python -m harness.orchestration.run a-mem mem--registers=benign,compliance
```
Алиас: `run.py poison` (старое имя).

## Находки
`F-POISON-GLOBAL` (critical, cross-tenant), `F-POISON-USER` (high, within-user), при black-box —
`F-POISON-BEHAVIORAL`. Отчёты: `report__mem.{json,md}` + сводный `output/POISON_PROOF.md`.
