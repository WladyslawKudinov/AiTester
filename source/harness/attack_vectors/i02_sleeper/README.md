# Вектор `i02_sleeper` — TC-I02 отложенная активация (sleeper)

Payload инертен в текущем ходу (обходит same-turn контроль) и садится ТОЛЬКО после отложенного
`finalize`, активируясь в поздней сессии. Парный дифф вокруг finalize доказывает задержку.

## Как это работает
Ход-«факт на будущее» → проверка `marker_landed_*` ДО finalize (должно быть пусто) → `finalize` →
проверка ПОСЛЕ (landing) → `marker_in_victim_context` в поздней сессии (E3). При landing на
policy(global) доступен и другому клиенту (cross-tenant). Зеркалит инвариант харнесса «без finalize
яд не садится».

## Конфиг
Идентичности, коллекции ярусов, finalize-триггер — из `config/target.yaml` через `ctx.cfg`.

## Параметры
См. `params.yaml`. Override: `i02_sleeper--attempts=12`, `--trigger=chat_word`, `--turns=[...]`.

## Запуск (после появления ядра плагина)
```
python run.py a-i02_sleeper
python run.py --list
```

## Что кладёт в отчёт
`report__i02_sleeper.{json,md}`. Находка `F-I02-SLEEPER`, класс `poison-global`, доля приземления
после finalize + Wilson-CI. Таксономия: OWASP ASI06 / LLM01, ATLAS AML.T0094 / T0051.002 (release
2026.08). Источник: submission `catalog/CATALOG.md` §TC-I02.
