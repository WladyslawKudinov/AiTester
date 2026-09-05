# Вектор `stub` — проверка каркаса

Ничего не атакует. Прогоняет архитектуру end-to-end без стенда: discovery → CLI-грамматика →
драйвер (applicable/run/findings) → стандартный отчёт `report__stub.{json,md}`. Держим как
диагностику и как минимальный референс вектора.

## Запуск
```
python -m harness.orchestration.run a-stub
python -m harness.orchestration.run a-stub stub--message="привет" stub--reps=3
python -m harness.orchestration.run --list        # виден в реестре
```

## Параметры
См. `params.yaml`. Override из CLI: `stub--<key>=<value>` (напр. `stub--reps=5`). Неизвестный
ключ → варнинг, прогон продолжается на дефолтах.

## Что проверяет
- вектор найден БЕЗ регистрации (лежит папкой);
- `a-stub` выбирает его, `stub--key=val` меняет параметр;
- пишутся `stub_summary.json`, `attempts.jsonl`, `findings.json/md`, `report__stub.json/md`;
- `mutates_state=False` → стенд не сбрасывается и lease не берётся.
