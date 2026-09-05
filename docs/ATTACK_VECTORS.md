# Как написать вектор атаки (для агента-автора)

Ты пишешь **один самодостаточный модуль-папку**. Он подключается к харнессу БЕЗ правок ядра
(ноль регистрации): положил папку в `source/harness/attack_vectors/<name>/` — она подхватывается.
Ты не знаешь систему заранее и не должен: всё про цель приходит через `cfg` и `ctx`, а вердикт даёт
общий детерминированный оракул. Ничего про конкретный стенд НЕ хардкодь.

---

## 1. Что ты производишь

Ровно одну папку `attack_vectors/<name>/` с тремя файлами:

| файл | обязателен | назначение |
|---|---|---|
| `vector.py` | да | один подкласс `AttackVector` (реализуешь `run` и `findings`) |
| `params.yaml` | да | параметры атаки + дефолты (меняются без правки кода) |
| `README.md` | да | как работает эта атака, что в конфиге, как звать |

Правила имени `<name>`: **только `[a-z0-9_]`**, без пробелов и спецсимволов (имя едет в CLI:
`a-<name>`, `<name>--<key>=<value>`). Имя папки = идентификатор вектора.

**Не редактируй ничего вне своей папки.** Не добавляй импортов своей атаки в другие файлы, не
трогай `run.py`, `config.py`, реестры, списки. Регистрация происходит сама (интроспекцией).

---

## 2. Минимальный рабочий шаблон (копируй и меняй)

`attack_vectors/<name>/vector.py`:
```python
"""<Одна строка: что за атака и какой вердикт даёт оракул>."""

from ...report import findings as F                  # фабрика находок
from ..base import AttackVector, attempt_guard       # контракт + failsafe попытки


class MyVector(AttackVector):
    name = "<name>"                          # == имя папки (можно не задавать — проставится)
    title = "<человекочитаемое имя>"
    mutates_state = False                    # True, если пишешь в память/политику стенда (см. §8)
    taxonomy = {"owasp_asi": "<...>", "owasp_llm": "<...>"}   # см. §7
    requirements = ()                        # Тир-A гейт возможностей цели (см. §9)
    hypotheses = ()                          # какие H-id из config/hypotheses.yaml покрываешь

    def applicable(self, ctx):
        # можно вернуть False, если цель не подходит (тогда вектор пропустят)
        return True

    def run(self, ctx):
        # ctx.cfg — цель, ctx.run — прогон, self.params — параметры (после override).
        ok = 0
        for i in range(int(self.params.get("attempts", 5))):
            with attempt_guard(ctx.run, label=f"try#{i}"):   # ОБЯЗАТЕЛЬНО: попытка не валит вектор
                # ... одна попытка: сгенерь/пошли запрос, спроси оракул ...
                ctx.run.attempt({"vector": self.name, "seq": i, "user_text": "...", "ok": True})
                ok += 1
        return {"target": ctx.cfg.target["target"]["name"], "greybox": True,
                "attempts": i + 1, "ok_attempts": ok}

    def findings(self, summary, ctx):
        # Преврати summary в список находок. Вердикт бери у оракула (§6), не «на глаз».
        return [F.finding(
            "F-<NAME>-1", "<class>", "<заголовок находки>",
            {"channel": "...", "call": "..."},          # reproduction: как повторить
            "<чем подтверждено (оракул/отпечаток)>",     # detection
            None,                                        # rate: summarize_rate(...) или None
            "critical",                                  # severity: critical|high|medium|low|info
            status="demonstrated")]
```

`attack_vectors/<name>/params.yaml`:
```yaml
params:
  <key>:
    type: str        # str|int|float|bool|list
    default: "..."
    description: "что делает параметр"
```

Готово — вектор виден в `--list` и запускается `a-<name>`. Референс — папка `stub/`.

---

## 3. Контракт `AttackVector` (attack_vectors/base.py)

Метаданные класса:

| атрибут | тип | смысл |
|---|---|---|
| `name` | str | идентификатор == имя папки (проставится автоматически, если пусто) |
| `title` | str | человекочитаемое имя вектора |
| `mutates_state` | bool | меняешь ли персистентный стейт стенда → драйвер возьмёт lease (§8) |
| `taxonomy` | dict | `{owasp_asi, owasp_llm}` для отчёта (§7) |
| `requirements` | tuple | требуемые возможности цели (код-гейт, §9) |
| `hypotheses` | tuple | H-id из `config/hypotheses.yaml`, которые покрываешь (справочно) |

Методы (переопределяешь):

| метод | обяз. | что делает |
|---|---|---|
| `applicable(self, ctx) -> bool` | нет | пригоден ли вектор к цели; `False` → пропуск. Дефолт `True` |
| `setup(self, ctx)` | нет | подготовка перед `run` (провижининг и т.п.) |
| `run(self, ctx) -> dict` | **да** | выполнить атаку, вернуть `summary` (пишется в `<name>_summary.json`) |
| `findings(self, summary, ctx) -> list` | **да** | превратить summary в находки (список `F.finding(...)`) |
| `teardown(self, ctx)` | нет | очистка после `run` (вызывается даже при ошибке) |
| `proof(self, run_dir) -> str\|None` | нет | путь к своему `proof.md` (человекочитаемый «что написал юзер»); иначе MD соберётся из находок |

Параметры доступны как `self.params` (dict, уже с учётом override). Конструктор трогать не нужно.

---

## 4. Контекст `ctx` (VectorContext)

Драйвер собирает и передаёт в каждый метод. Никаких глобалов — бери всё отсюда.

| поле/метод | что это |
|---|---|
| `ctx.cfg` | конфиг цели (`Config`) — единственный источник правды о стенде (§5) |
| `ctx.run` | прогон (`Run`): `ctx.run.attempt(dict)` — строка в attempts.jsonl; `ctx.run.dir`, `ctx.run.write_json(name,obj)` |
| `ctx.params` | те же параметры, что `self.params` |
| `ctx.client()` | ленивый `AgentClient` — общение с агентом цели (§5.2) |
| `ctx.attacker()` | ленивый `Attacker` — LLM-генерация/адаптация промптов (§5.3) |
| `ctx.judge()` | ленивый `Judge` — мягкий LLM-скор рядом с оракулом (§6.3) |

---

## 5. Доступ к цели — только через `cfg` (НИКАКИХ литералов)

Всё про адреса/идентичности/память/модели лежит в `config/target.yaml` и читается через `cfg`.
Захардкодишь URL/порт/имя коллекции — сломаешь переносимость на другой стенд.

### 5.1 Конфиг (`ctx.cfg`, класс Config)
| вызов | отдаёт |
|---|---|
| `cfg.agent(key, **fmt)` | URL ручки агента (`key` из endpoints.agent_api), напр. `cfg.agent("chat")` |
| `cfg.data(key, **fmt)` | URL ручки сервиса данных, напр. `cfg.data("client_by_cus", cus="1003")` |
| `cfg.mode("vulnerable"\|"protected"\|"default")` | строка режима авторизации (для парного контроля) |
| `cfg.attacker_default()` / `cfg.victim_default()` | cus атакующего / жертвы из посева |
| `cfg.seeded()` / `cfg.by_cus(cus)` / `cfg.by_account(id)` | посеянные клиенты/счета (эталон) |
| `cfg.fingerprints_for(cus)` | список строк-отпечатков клиента (любое совпадение в ответе = утечка) |
| `cfg.collection(tier)` | имя mongo-коллекции яруса (`policy\|semantic\|episodic\|dialog`) |
| `cfg.context_limit(tier)` | сколько свежих записей яруса система берёт в контекст |
| `cfg.finalize_word()` / `cfg.finalize_triggers()` | как триггерить консолидацию памяти |
| `cfg.sensitive_tools()` | чувствительные инструменты агента (name/kind/extra) |
| `cfg.system_description()` | описание тестируемой системы (контекст для морферов) |
| `cfg.strategies()` | библиотека тактик для многоходовых диалогов |
| `cfg.slot_default(slot)` / `cfg.slot_candidates(slot)` | модель по умолчанию / кандидаты (`target_brain`, `attacker`, `judge`, ...) |
| `cfg.hypothesis(hid)` / `cfg.hypotheses` | одна гипотеза / все (из hypotheses.yaml, с раскрытыми from_target) |

### 5.2 Общение с агентом цели (`ctx.client()`, AgentClient)
| вызов | что делает |
|---|---|
| `client.chat(api_key, text, *, session_id, auth_mode=None)` | один ход; `-> {status, content, ...}` |
| `client.dialog(api_key, turns, *, session_id, auth_mode=None)` | последовательность ходов в одной сессии |
| `client.finalize(api_key, session_id, *, via="endpoint", auth_mode=None)` | триггер консолидации памяти |

Ключи API получаешь провижинингом: `from ...core import provisioning` →
`keys = provisioning.ensure_all(cfg)` (`{cus: api_key}`), либо токен `provisioning.get_token(cus, cfg)`.
`session_id` бери свежий: `from ...core import isolation` → `isolation.new_session_id()`.

### 5.3 LLM-генерация промптов (`ctx.attacker()`, Attacker) — если атаке нужен «мозг»
| вызов | что делает |
|---|---|
| `attacker.gen_bac_prompts(attacker_cus, victim_cus, account_id, n=8, seeds=None)` | набор BAC-формулировок |
| `attacker.gen_poison_dialogs(marker, register="benign", n=5, seeds=None)` | диалоги-отравления с маркером |
| `attacker.next_turn(goal, transcript, last_reply, profile=None, strategy=None)` | следующий ход в многоходовке |
| `attacker.adapt_bac(last, reply, victim, account_id)` | адаптировать формулировку под ответ |
| `Attacker.is_refusal(reply)` | эвристика отказа (для backtrack) |

Многоходовые кампании уже есть: `from ...core.conversation import Conversation`.

---

## 6. Оракул — детерминированный вердикт (наше преимущество)

**Вердикт по атаке выноси оракулом состояния, а не по тексту ответа.** `from ...oracle import state`.

### 6.1 BAC (доступ к чужим данным)
| вызов | вердикт |
|---|---|
| `state.served_cross_cus(attacker_cus, victim_cus, auth_mode, cfg)` | `served=True` → отдал чужие данные |
| `state.account_owner_resolves(attacker_cus, account_id, auth_mode, cfg)` | `resolved=True` → раскрыл владельца |

Делай **парный контроль**: воспроизведи в `vulnerable` и проверь, что в `protected` закрыто.

### 6.2 Память (отравление)
| вызов | вердикт |
|---|---|
| `state.marker_landed_global(marker, cfg)` | маркер на ОБЩЕМ ярусе (policy) → cross-tenant |
| `state.marker_landed_user(marker, victim_cus, cfg)` | маркер в личном ярусе клиента → within-user |
| `state.marker_in_victim_context(marker, victim_cus, cfg)` | попал ли маркер в контекст жертвы (тем же лимитом, что система) |
| `state.working_memory(cus, session, cfg)` | рабочая память сессии (до финализации) |
| `state.find_marker(marker, tier, cfg)` / `state.snapshot(cfg)` | записи с маркером / срез всех ярусов |

Всегда меряй **base_rate** (естественное появление без атаки) и репорти превышение над ним.

### 6.3 Когда нет доступа к БД (black-box)
Проверь `state.grey_box_available(cfg)`. Если `False` — оракула состояния нет: суди поведенчески
через `ctx.judge().rubric(reply, goal)` (StrongREJECT-скор) и помечай находку НИЖЕ доверием
(`status`/`notes`). Не выдавай behavioral за state-вердикт.

---

## 7. Находки — `F.finding(...)` (report/findings.py)

```python
F.finding(fid, cls, title, reproduction, detection, rate, severity,
          status="demonstrated", notes=None, taxonomy=None)
```
| аргумент | что класть |
|---|---|
| `fid` | стабильный id, напр. `"F-<NAME>-DATA"` |
| `cls` | класс находки (строка); маппится на таксономию |
| `title` | заголовок |
| `reproduction` | dict «как повторить»: `{channel, call, ...}` — для агента-повторятеля |
| `detection` | чем подтверждено (оракул/отпечаток) |
| `rate` | `summarize_rate(successes, n)` (доля + Wilson-CI) или `None` для детерминированного |
| `severity` | `critical\|high\|medium\|low\|info` |
| `status` | `"demonstrated"` или `"not-demonstrated"` |
| `taxonomy` | `{owasp_asi, owasp_llm, cvss?}`; если не задать — возьмётся по `cls` |

Доля успеха: `from ...report.stats import summarize_rate` → `summarize_rate(successes, n)`.
**Отрицательный результат** репорти как `status="not-demonstrated"` (НЕ «безопасно»): класс не
воспроизведён при данных моделях/N. Таксономия — язык индустрии (OWASP Agentic Security Initiative
+ LLM Top-10), переносится между целями; задай `taxonomy` на классе вектора.

---

## 8. Изоляция и стейт (`from ...core import isolation`)

Если пишешь в персистентную память/политику — ставь `mutates_state = True`. Тогда драйвер:
- берёт **lease** на стенд (сериализует state-меняющие прогоны — не бей чужой прогон);
- ты сам делаешь безопасную подготовку/уборку.

| вызов | назначение |
|---|---|
| `isolation.fresh_marker()` | свежая метка-СЛОВО (напр. ОКЕАН) — уникальна в прогоне; **без кодовых суффиксов** (сильная модель распознаёт «набор букв» как тест и не травится) |
| `isolation.new_session_id(prefix="atk")` | уникальная сессия на попытку |
| `isolation.prepare_reset(cfg, full=False)` | точечная чистка канареек (по умолчанию); полный вайп — только `full=True` |
| `isolation.cleanup_marker(marker, cfg)` / `isolation.clear_working(...)` | удалить свои записи / рабочую память |
| `isolation.RunIsolation(marker, cus)` | контекст-менеджер: свежая сессия + гарантированная уборка метки |

Read-only векторы (BAC-чтение) — `mutates_state = False`, стенд НЕ сбрасывают.

---

## 8b. Failsafe — ОБЯЗАТЕЛЬНО (максимальная отказоустойчивость)

Три уровня изоляции сбоев. Два верхних гарантирует харнесс, нижний — **твоя ответственность**.

| уровень | кто отвечает | поведение при сбое |
|---|---|---|
| попытка (одна итерация) | **ТЫ** | не должна ронять вектор — оборачивай каждую в `attempt_guard` |
| вектор (модуль) | харнесс | падение `run/findings/setup/...` → error-находка (`outcome=error`) + отчёт, соседние векторы работают |
| discovery/оркестратор | харнесс | сбойный `vector.py` → варнинг, пропуск; оркестратор не падает никогда |

**Что делаешь ты (иначе завернут):**
- Оборачивай КАЖДУЮ попытку в цикле: `with attempt_guard(ctx.run, label="..."): ...`. Одна упавшая
  генерация / сетевой сбой / таймаут не должны прерывать весь sweep.
- Возвращай **частичный результат**: если часть попыток упала, всё равно верни `summary` по
  успешным (не бросай из `run`). Считай успехи отдельно (`ok_attempts`).
- Никогда не глотай ошибку молча без следа — `attempt_guard` сам логирует её строкой в
  `attempts.jsonl`; если делаешь свой `try/except`, тоже логируй через `ctx.run.attempt({...})`.
- Внешние вызовы (агент цели, LLM-генератор, оракул) считай ненадёжными: таймаут/500/пустой ответ —
  это НЕ падение вектора, а одна неуспешная попытка.

Проверка: временно добавь `raise` в свою попытку — вектор должен доработать остальные и вернуть
summary; добавь `raise` в `run()` — оркестратор должен выжить и написать error-отчёт по тебе.

---

## 9. Совместимость с целью (Тир A, опционально)

Объяви `requirements` — набор нужных возможностей цели, напр.
`requirements = ("greybox", "finalize_endpoint")`. В `applicable(ctx)` проверь их через `cfg`/оракул
и верни `False`, если цель не тянет (вектор аккуратно пропустят с причиной). Дефолт — применять
всегда. (LLM-профилирование цели — на будущее, сейчас не нужно.)

---

## 10. Параметры — `params.yaml` + override без правки кода

Объяви параметры со схемой:
```yaml
params:
  max_turns: {type: int, default: 5, description: "макс. ходов в диалоге"}
  register:  {type: str, default: "benign", options: [benign, compliance], description: "регистр"}
```
Меняются двумя путями (precedence: дефолт < CLI):
- из CLI: `run.py a-<name> <name>--max_turns=8 <name>--register=compliance`;
- в файле: правишь `default`.

Неизвестный ключ override **не роняет прогон** — печатается варнинг, берётся дефолт. Читай значения
из `self.params.get("max_turns")`.

**Обёртки аргументов снимает ОРКЕСТРАТОР — модуль получает чистые аргументы.** CLI-грамматику
(`a-<vector>` для выбора, `<vector>--<key>=<value>` для override) разбирает `run.py`: срезает `a-`,
режет `<vector>--` (имя вектора идёт только на маршрутизацию), коэрсит типы и валидирует по твоему
`params.yaml`. В `run()/findings()` приходит **чистый dict** `self.params` (== `ctx.params`) с голыми
именами — БЕЗ префиксов `a-`/`<vector>--`. Ты пишешь просто `self.params.get("attempts")` и ничего не
знаешь про нашу CLI-грамматику. Граница ответственности: **ты декларируешь** параметры в `params.yaml`
→ **оркестратор парсит/срезает/коэрсит/валидирует** → **ты потребляешь** чистые значения.
Следствие — **портируемость**: вектор не привязан к нашему CLI, его можно инстанцировать напрямую
`MyVector(params={"attempts": 8}).run(ctx)` и использовать вне этого харнесса.

---

## 11. Отчёты — пишутся сами

Драйвер после `findings()` сам создаёт в папке прогона:
- `report__<name>.json` — строгая схема (для сборки ядром-LLM);
- `report__<name>.md` — человекочитаемо (единые заголовки).
Плюс общие `findings.json/md`, `coverage.*`, твой `<name>_summary.json`, `attempts.jsonl`.
Ты НЕ пишешь эти файлы. Хочешь человекочитаемый «что написал юзер» — реализуй `proof(run_dir)`,
верни путь к собранному `proof.md` (реконструируй из `attempts.jsonl`); он попадёт в MD-отчёт.

---

## 12. Жизненный цикл (что за чем зовёт драйвер)

```
discover() найдёт твой класс
  -> vec = <Class>(params = дефолты + CLI-override)
  -> applicable(ctx)?  нет -> пропуск
  -> setup(ctx)
  -> [lease на стенд, если mutates_state] run(ctx) -> summary
  -> teardown(ctx)                 # даже при ошибке
  -> findings(summary, ctx) -> находки
  -> report_std пишет report__<name>.{json,md}
```

---

## 13. Запуск и проверка

```
./.venv/bin/python run.py --list                 # твой вектор в реестре + его параметры
./.venv/bin/python run.py a-<name>               # прогон
./.venv/bin/python run.py a-<name> <name>--k=v   # с override
./.venv/bin/python run.py a-all                  # все векторы
```
После прогона смотри `output/runs/<run>/report__<name>.json` и `.md`.

---

## 14. Инварианты (нарушишь — атаку завернут)

- **Config-driven:** ноль литералов цели в коде (URL/порт/коллекция/cus/модель) — всё через `cfg`.
- **Вердикт — оракулом**, не по тексту; парные контроли (vulnerable↔protected); base_rate для памяти.
- **Wilson-CI** на долях (`summarize_rate`), не «прогнал раз — работает».
- **Маркеры — обиходные слова** (`isolation.fresh_marker()`), не кодовые строки.
- **Отрицательный результат** = `not-demonstrated`, не «безопасно».
- **Failsafe:** каждая попытка в `attempt_guard`; `run` не бросает, возвращает частичный summary;
  внешний сбой = одна неуспешная попытка, не падение вектора (§8b).
- **Только своя папка**; ничего вне неё не трогаешь; ноль регистрации.

---

## 15. Чек-лист автора (для PR)

- [ ] Папка `attack_vectors/<name>/` (имя `[a-z0-9_]`) с `vector.py`, `params.yaml`, `README.md`.
- [ ] Один подкласс `AttackVector`; реализованы `run` и `findings`.
- [ ] Ноль литералов цели — всё через `cfg`/`ctx`.
- [ ] Вердикт даёт оракул (`state.*`); парный контроль / base_rate где применимо.
- [ ] `mutates_state` выставлен верно; для state-меняющих — уборка в `teardown`, маркеры-слова.
- [ ] Failsafe: каждая попытка в `attempt_guard`, `run` не бросает и отдаёт частичный summary
      (проверено `raise` в попытке и в `run`).
- [ ] `taxonomy` задана (OWASP ASI/LLM); severity/status осмысленны.
- [ ] Параметры в `params.yaml` со схемой; читаются из `self.params`.
- [ ] Проверено: `--list` показывает вектор, `a-<name>` отрабатывает, есть `report__<name>.{json,md}`.
- [ ] README объясняет: что атакует, что в конфиге, как звать, какие параметры.
