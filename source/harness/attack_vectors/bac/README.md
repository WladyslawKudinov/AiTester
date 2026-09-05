# Вектор `bac` — межклиентский доступ (BOLA), 3 канала

Проверяет, отдаёт ли система данные ОДНОГО клиента другому (Broken Access Control / BOLA).

## Как это работает
- **data_layer** (детерминированный): токен атакующего → `client_by_cus(victim)`. Вердикт — оракул
  состояния, парный контроль `vulnerable`↔`protected` (`served_cross_cus`).
- **account_owner** (детерминированный): резолв владельца чужого счёта; часто течёт и в `protected`.
- **agent_mediated** (LLM→tool): агент подставляет чужой `cus/account` в инструмент; вердикт по
  отпечаткам жертвы в ответе (не эхо запроса), доля + Wilson-CI, опц. многоходовый диалог.

Read-only — стенд НЕ сбрасывается (`mutates_state=False`).

## Конфиг
Всё из `config/target.yaml` через `cfg`: endpoints (agent/data), `identities` (attacker/victim/
account, отпечатки), `auth_modes` (vulnerable/protected). Ноль литералов.

## Параметры
См. `params.yaml`. Пример: `run.py a-bac bac--attempts=8 bac--multiturn=true`.

## Запуск
```
python -m harness.orchestration.run a-bac
python -m harness.orchestration.run a-bac bac--multiturn=true bac--max_turns=6
```
Алиас: `run.py bac` (старое имя).

## Находки
`F-BAC-DATA` (critical, парный), `F-BAC-OWNER` (high, течёт в protected), `F-BAC-AGENT` (critical,
доля+CI). Отчёты: `report__bac.{json,md}` + сводный `output/PROOF.md` («что написал юзер» + REST).
