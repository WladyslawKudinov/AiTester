# Вектор `<name>` — TODO: одна строка сути

TODO: что атакует, какой вердикт даёт оракул, к каким целям применим.

## Как это работает
TODO: канал (data-layer / agent-mediated / finalize→память / …), что шлётся, чем подтверждается
(оракул состояния — `served_cross_cus` / дифф ярусов / отпечатки).

## Конфиг
Что берётся из `config/target.yaml` через `cfg` (адреса, идентичности, ярусы). Ноль литералов.

## Параметры
См. `params.yaml`. Override из CLI: `<name>--<key>=<value>` (напр. `<name>--attempts=8`).
Неизвестный ключ → варнинг, дефолт.

## Запуск
```
python -m harness.orchestration.run a-<name>
python -m harness.orchestration.run a-<name> <name>--attempts=8
python -m harness.orchestration.run --list
```

## Что кладёт в отчёт
`report__<name>.{json,md}` в папке прогона (пишет драйвер). Находки — с таксономией OWASP ASI/LLM,
долей + Wilson-CI, статусом demonstrated/not-demonstrated.

> Полная инструкция автора: `docs/ATTACK_VECTORS.md`.
