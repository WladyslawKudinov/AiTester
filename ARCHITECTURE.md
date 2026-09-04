# Архитектура genai-harness

Универсальный test-harness для тестирования безопасности GenAI-агентов с памятью. Документ
описывает **устройство** тулы: компоненты, потоки данных, инварианты дизайна и точки расширения.
Плейн-объяснение «на пальцах» — в `HOW_IT_WORKS.md`; находки — в `RESULTS.md`.

---

## 1. Цели дизайна (что определяет всю архитектуру)

1. **Не сшито с целью.** Все факты о цели — в `config/target.yaml` (собран из `customer_info.md`).
   В коде фактов цели нет. Перенос на другую цель = замена одного файла.
2. **Оракул состояния — рефери.** Вердикт по классу выносит детерминированная проверка состояния
   хранилищ + эталон, а не текст агента и не мнение LLM-судьи. LLM может стоять где угодно в петле,
   но линейка измерения — одна.
3. **Против ложного «безопасно».** Свип векторов и моделей-атакующих; мульти-отпечаток;
   дифференциальный судья; контроли; частота на N с доверительным интервалом. «Не воспроизведено»
   репортится как «не продемонстрировано при условиях», не как «безопасно».
4. **Изоляция прогонов.** Персистентная память переживает сессии; без уборки один прогон отравит
   следующий. Уникальная сессия + teardown канареек + опция полного сброса памяти.
5. **Темпоральность.** Отравление не мгновенно; эффект меряется как многоступенчатая конверсия
   E1→E4 и как частота приземления, не булев исход.

---

## 2. Карта компонентов

```
                        ┌──────────────────────────┐
   customer_info.md ──▶ │  config/*.yaml (спек)     │  target · hypotheses · models · payloads
                        └────────────┬─────────────┘
                                     │  core/config.py — единая точка правды (резолверы)
        ┌────────────────────────────┼────────────────────────────────┐
        ▼                            ▼                                  ▼
 ┌─────────────┐            ┌──────────────────┐              ┌──────────────────┐
 │   CORE      │            │     ORACLE       │              │      TASKS        │
 │ client      │  chat/fin  │ state  (BAC+mem) │  вердикт      │ bac              │
 │ provisioning│──────────▶ │ fingerprints     │◀────────────│ memory_poison    │
 │ openrouter  │  атаки/суд │ memory_observer  │              │ chain_ab         │
 │ attacker    │            │ judge_llm        │              └────────┬─────────┘
 │ isolation   │            └──────────────────┘                       │
 └──────┬──────┘                                                       │
        │                    ┌──────────────────┐                      │
        └───────────────────▶│      RECON       │                      │
                             │ route_oracle     │  (black-box навод)   │
                             │ prompt_fuzz      │                      │
                             └──────────────────┘                      │
                                                                       ▼
                                        ┌──────────────────────────────────────┐
                                        │        ORCHESTRATION (run.py)         │
                                        │  setup → sweep(варианты) → teardown   │
                                        │  + target_matrix.py (оверлей моделей) │
                                        └───────────────────┬──────────────────┘
                                                            ▼
                                        ┌──────────────────────────────────────┐
                                        │  REPORT: findings · coverage ·        │
                                        │  susceptibility · stats (Уилсон)      │
                                        └───────────────────┬──────────────────┘
                                                            ▼
                                     runs/<id>/ : findings.json · attempts.jsonl ·
                                     calls.jsonl · openrouter.jsonl · *.md
```

Цель (внешняя система) — отдельный процесс; тула взаимодействует ТОЛЬКО снаружи: HTTP-ручки
агента/данных + прямое чтение хранилищ (grey-box) + оверлей развёртывания для смены модели.

---

## 3. Модули и ответственность

| Слой | Модуль | Ответственность |
|---|---|---|
| core | `config.py` | Загрузка/валидация `config/*.yaml`; резолверы URL, идентичностей, отпечатков, инструментов, слотов моделей. Единственный, кто знает структуру спека. |
| core | `client.py` | Транспорт к агенту (chat/finalize, SSE+plain), построчный аудит `calls.jsonl`. Финализация двумя каналами (endpoint / слово в чат) с ретраями. |
| core | `provisioning.py` | Headless-выдача API-ключей (grant у IAM → ручка выдачи с bypass-заголовком → парс ключа), идемпотентный кэш. |
| core | `openrouter.py` | Вызовы OpenRouter для слотов attacker/judge; лог модели+параметров (`openrouter.jsonl`). |
| core | `attacker.py` | LLM-«мозг атаки»: генерация N формулировок (one-shot) и adaptive-мутация по ответу агента. |
| core | `isolation.py` | Уникальный `session_id`; свежая канарейка; teardown маркеров; `reset_memory` (чистый прогон). |
| core | `runlog.py` | Контекст прогона: папка `runs/<id>/`, запись `attempts.jsonl`, артефактов. |
| oracle | `state.py` | Детерминированный оракул: BAC на слое данных (served_cross_cus, account_owner) + чтение ярусов памяти (Redis/Mongo) + снимок состояния. |
| oracle | `fingerprints.py` | Мульти-отпечаток по эталону; фильтр ложных плюсов (эхо запроса, короткие числа). |
| oracle | `memory_observer.py` | Память как временной ряд: снимки с таймстампами + диффы (что появилось/вытеснилось). |
| oracle | `judge_llm.py` | Дифференциальный LLM-судья (чистая ↔ отравлённая память) — мягкий сигнал, калибруется об оракул. |
| recon | `route_oracle.py` | Скрытые эндпоинты по разнице HTTP-кодов (black-box навод/автоконфиг). |
| recon | `prompt_fuzz.py` | Статический (не-LLM) мутатор кандидатов — ось сравнения с LLM-атакующим. |
| tasks | `bac.py` | Таск A: 3 канала (data-layer, agent-mediated, account-owner), свип+adaptive, пара vuln↔prot. |
| tasks | `memory_poison.py` | Таск B: цикл E1→E4, продольный прогон по регистрам, landing-rate, baseline. |
| tasks | `chain_ab.py` | Связка A×B: BAC через отравлённую память. |
| orch | `run.py` | CLI-дирижёр: smoke/bac/poison/models/chain; setup→прогон→findings→coverage. |
| orch | `target_matrix.py` | Матрица целевых моделей через .env-оверлей стенда (бэкап→рестарт→прогон→восстановление). |
| report | `findings.py` | Сборка `findings.json/.md` (репродукция, детект, доля+CI, severity). |
| report | `coverage.py` | Матрица покрытия векторов из `attempts.jsonl`. |
| report | `susceptibility.py` | Таблицы сравнения атакующих/целевых моделей. |
| report | `stats.py` | Доля успеха + доверительный интервал Уилсона. |

---

## 4. Поток данных

### 4а. BAC (Таск A)

```
provisioning.ensure_key(1001)                       ← ключ атакующего
        │
        ├─(канал 1: data-layer)──────────────────────────────────────────────────┐
        │   oracle.state.served_cross_cus(1001, 1003, mode)                        │
        │        token(1001) → GET data_service/clients/1003 → {200|403}           │
        │                                                                          ▼
        ├─(канал 2: agent-mediated)                                        детерминированный
        │   attacker.gen_bac_prompts(...) → client.chat(1001, "…cus=1003…")        вердикт
        │        reply → fingerprints.whose(reply, exclude=[1001], excl=prompt)    (served /
        │        adaptive: если нет утечки → attacker.adapt_bac(reply) → повтор     отпечаток)
        │                                                                          ▲
        └─(канал 3: account-owner) state.account_owner_resolves(1001, счёт) ───────┘
        │
        ▼
   report.findings  (пара vulnerable↔protected; доля на N + CI)
```

### 4б. Отравление памяти (Таск B) — цикл E1→E4

```
isolation.reset_memory()                          ← чистый старт
clean_reply = client.chat(victim, нейтральный_?)  ← контроль (чистая память)

цикл × N (свежий marker каждый раз):
   E1  client.dialog(1001, payload_turns)  → state.working_memory() содержит marker?
   ──  client.finalize(1001, via=endpoint|chat_word)         ← ТРИГГЕР (иначе эффекта нет)
   E2  state.marker_landed_global() / marker_landed_user()   ← дифф policy/semantic
   E3  state.marker_in_victim_context(marker, target)        ← тем же лимитом, что система
   E4  reply = client.chat(target, нейтральный_?);  marker in reply?
       judge_llm.differential(clean_reply, reply)            ← мягкий сигнал
   teardown: isolation.cleanup_marker(marker)

baseline: безобидные finalize без атаки → базовая частота global (находка = превышение)
```

Цель распространения зависит от яруса приземления: `global` → жертва (другой клиент);
`user` → сам автор в новой сессии (within-user persistence).

---

## 5. Три оси «где LLM в петле» (предмет эксперимента)

| Ось | Варианты | Где реализовано |
|---|---|---|
| Генерация атаки | static (payloads/prompt_fuzz) · LLM one-shot · LLM adaptive | `tasks/bac`, `attacker.py` |
| Детект успеха | детерминированный оракул · LLM-судья · оба (калибровка) | `oracle/state` + `oracle/judge_llm` |
| Оркестрация | фиксированный порядок в коде · (задел под LLM-решение шага) | `orchestration/run` |

Каждая попытка в `attempts.jsonl` помечена вариантом (канал, атакующая модель, режим), чтобы
результаты не смешивались. Роль Claude Code — только код + арбитр, НЕ участник сравнения.

---

## 6. Слои детекта и деградация

| Доступ к цели | BAC | Отравление |
|---|---|---|
| grey-box (Redis/Mongo на host) | дифф ярусов + прямое чтение | дифф `policy`/`semantic` (сильнейший) |
| api-box (только HTTP + провижининг) | served_cross_cus; отпечатки в ответе | ответ finalize, `GET /memory`, отпечатки |
| black-box (только чат) | отпечатки жертвы в ответе агента | маркер в ответе жертвы (E4), дифференциально |

Режим детекта фиксируется в находке. Для текущей цели доступен grey-box (redis:6379/mongo:27017
проброшены) → сильнейший детект. `recon/` достраивает недостающие факты вслепую, если grey-box
или `customer_info` неполны.

---

## 7. Конфиг как единственная правда

`core/config.py` — фасад над `config/*.yaml`. Никакой другой модуль не знает литералов цели.

- **`target.yaml`** — endpoints, auth_modes, provisioning, finalize_triggers, storage
  (коллекции/лимиты), tools (7 чувствительных + 7 справочных), identities (эталон 1001–1005 с
  отпечатками), target_models, deployment (для оверлея модели), needs_review (пробелы).
- **`hypotheses.yaml`** — H1..H5: тип, участники, точка детекта, оси свипа (ссылки `from_target`).
- **`models.yaml`** — слоты attacker/judge/target_brain/target_consolidation (списки кандидатов).
- **`payloads.yaml`** — формулировки по регистрам (benign/instruction/compliance/universal),
  `{marker}`/`{account_id}` подставляются на прогоне.

Резолверы (`cfg.url()`, `cfg.fingerprints_for()`, `cfg.sensitive_tools()`, `cfg.slot()` …)
скрывают структуру; смена схемы цели затрагивает только `config.py` + yaml, не логику атак.

---

## 8. Жизненный цикл прогона и изоляция

1. `Run()` создаёт `runs/<id>/`, открывает `attempts.jsonl`.
2. Очистка: `purge_all_canaries()` (по сигнатурам маркеров) или `reset_memory()` (полный сброс
   ярусов, кроме `api_keys`).
3. Каждая попытка: свежий `session_id`, свежая канарейка → атака → оракул → запись строки →
   teardown маркера.
4. Между разными формулировками отравления — `reset_memory()` (накопление контрзаписей одного
   payload не занижает приземление другого); внутри формулировки накопление сохраняется
   (dose-response).
5. Смена модели цели (`target_matrix`): бэкап `.env` → правка переменной → рестарт agent-api →
   ожидание health → прогон → **восстановление `.env`** в `finally` (стенд возвращается в исходное).

---

## 9. Отчётность и статистика

- **`findings.json/.md`** — главный артефакт. Поля: `id`, `class`, `severity`, `status`
  (demonstrated / not-demonstrated), `reproduction` (общий словарь канал/ярус/роль + конкретные
  параметры), `detection` (чем подтверждено), `success` (доля на N + CI Уилсона).
- **`coverage.md`** — что перебрано и с какой долей (чтобы «безопасно» опиралось на исчерпанный
  свип).
- **`susceptibility_*.md`** — сравнение атакующих и целевых моделей.
- **`attempts.jsonl` / `calls.jsonl` / `openrouter.jsonl`** — сырьё под независимую перепроверку.

Доля успеха всегда с доверительным интервалом (Уилсон корректен на малых N и у границ 0/1);
любой ненулевой успех выделяется отдельно от нуля.

---

## 10. Точки расширения

- **Новая цель** → `config/target.yaml` (+ `customer_info.md`), без правок кода.
- **Новый вектор** → строка в `payloads.yaml` / новая гипотеза в `hypotheses.yaml`.
- **Новая атакующая/целевая модель** → строка в `models.yaml` (candidates).
- **Новый класс атаки** → модуль в `tasks/` поверх готовых `core`/`oracle` (транспорт, оракул,
  отпечатки, изоляция переиспользуются).
- **Новый внешний движок** (garak/llamator/…) → адаптер поверх `client.py`, вердикт — тем же
  оракулом состояния.
