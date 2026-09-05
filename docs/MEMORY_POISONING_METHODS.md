# Методы генерации атак отравления памяти — обзор и план усиления

_Исследование под aitest_cui (грей-бокс харнесс тестирования GenAI-агента с многоярусной памятью).
Три параллельных агента: (A) генерация в установленных тулах по коду, (B) академические методы,
(C) таксономия + критика нашего подхода. Дата: 2026-09-05._

## TL;DR — вердикт

Наш текущий метод генерации отравления — **«дать инструкцию атакующей LLM → вернуть диалог»**
(`core/attacker.py:_POISON_GEN`, `gen_poison_dialogs`) — это категория **(b) LLM-морфер, open-loop**.
Для разового джейлбрейка ок, но для ОТРАВЛЕНИЯ ПАМЯТИ это слабейшее звено: генерим вслепую, без
сигнала «записалось / стало global / всплыло у другого клиента». **Главный разрыв: у нас УЖЕ есть
детерминированный state-оракул (`oracle/state.py`), но он НЕ заведён в цикл генерации.** Починка
этого — самый дешёвый и мощный шаг.

Отравление памяти имеет **два гейта успеха** (обычные джейлбрейк-методы оптимизируют лишь первый и
то частично):
- **write-time:** запись легла в память без отказа-контрзаписи и с нужным scope (global для
  cross-tenant);
- **read-time:** запись отобрана ретривером у ДРУГОГО клиента и повлияла на ответ.

## Таксономия методов генерации (ось: как порождается нагрузка)

| Категория | Как генерит | Что оптимизирует / сигнал | Нужен доступ | Пригодность для ПАМЯТИ |
|---|---|---|---|---|
| **(a) Handcrafted/шаблоны** | кураторские сиды, ролевые обёртки (DAN, AdvBench) | ничего; отбор «сработало у людей» | API | **низк.** — только сиды; сильная модель детектит → контрзапись |
| **(b) LLM-морфер** ← мы | атакующая модель пишет/переписывает по промту | разнообразие/уклонение; **сигнала о приземлении нет (open-loop)** | API | **сред.** — естеств. язык переживает консолидацию; обфускация/перевод ВРЕДЯТ памяти |
| **(c) Оптимизация** (GCG/AutoDAN/GBDA) | поиск токенов суффикса/триггера (gradient/genetic) | P(target-ответ) по loss/логитам/fitness | веса+градиенты (перенос в ЧЯ) | **низк. как есть** — «салат» детектится/не переживает консолидацию; ценен КАРКАС поиска при fitness=оракул |
| **(d) Retrieval/embedding-aware** | подгон текста под кластер запросов жертвы | sim(payload, запросы жертвы)+P(target) | белый ящик эмбеддера (перенос) | **выс.** — прямо решает «всплыть у другого клиента» |
| **(e) Многоходовые** (Crescendo/PAIR/TAP/GOAT/MINJA) | атакер порождает след. ход из ответа цели | судья/reward; откат на отказе | API | **сред.–выс.** — цикл с обратной связью + write-путь MINJA |

## Что делают установленные тулы (по исходному коду)

| Тул | (a) | (b) LLM-морфер | (c) оптим. | (d) RAG-aware | (e) многоход | Про ПАМЯТЬ конкретно |
|---|---|---|---|---|---|---|
| **garak** | latentinjection, promptinject, dan | TAP/GOAT/atkgen, buffs/paraphrase | GCG, BEAST, AutoDAN | position-in-doc (не embedding) | TAP, GOAT | нет persistence-probe; лучший ген инъекций В ДОКУМЕНТ |
| **pyrit** | many_shot, skeleton_key | ~20 converters, fuzzer(MCTS) | GCG token-grad | — | Crescendo/PAIR/TAP; **xpia** | **xpia** = примитив доставки stored/indirect (запись в стор → отложенный read) |
| **deepteam** | context_flooding | **ContextPoisoning, SyntheticContextInjection, indirect_instruction** | LLM-judge (не gradient) | контент «как retrieved» | Crescendo/linear/tree | **сильнейшие purpose-built морферы отравления памяти/контекста** |
| **llamator** | parquet-корпуса (GCG-replay, dan) | AutoDAN-Turbo, CoP, PAIR | AutoDAN-Turbo (эволюция), BoN | Jaccard-новизна | Crescendo/PAIR/CoP | слаб для памяти: таргет stateless (`use_history=False`) |
| **promptfoo** | cross-session-leak, prompt-extraction | Crescendo/iterative inline | PAIR, TAP | **poison-document, rag-poisoning** | **agentic:memory-poisoning** | сквозная оркестрация memory→poison→follow-up, но за облачным API |

**Кто сильнее по нашей оси:**
- **Генерация пейлоада для памяти → deepteam.** `ContextPoisoning` (промт: «harmful action has ALREADY
  been approved/completed/validated»), `SyntheticContextInjection` (фабрикует прошлую сессию/
  RAG-evidence/логи, мимикрия под внутренние структуры). Локально, бесплатно. Минус — только препенд
  в одно сообщение, в реальный стор не пишет.
- **Доставка+отложенная проверка → PyRIT `xpia`** (`workflow/xpia.py`): `attack_setup_target` кладёт
  контент в стор, `processing_callback` заставляет жертву прочитать его ПОЗЖЕ. Пейлоад подаёшь свой.
- **Оркестрация → promptfoo** `agentic:memory-poisoning`: seed-memory → poison → dependent follow-up,
  критерий «отравлено, если follow-up отвечен неверно».
- **Никто не делает true embedding-оптимизацию под ретривер** — это остаётся преимуществом, если
  портировать AgentPoison (нужен белый ящик эмбеддера).

## Академические методы (как оптимизируют нагрузку)

| Метод | Тип генерации | Доступ к весам/эмбеддеру | Чисто диалоговое отравление общей памяти? |
|---|---|---|---|
| **Corpus Poisoning** (Zhong+ EMNLP’23) | (c) HotFlip + (d) k-means по запросам | да (white-box ретривер) | нет (нужна запись в корпус + white-box) |
| **PoisonedRAG** (USENIX’25) | (b) LLM для gen-части + (d); white-box +(c) | опц. (ЧЯ есть) | частично (нужен канал записи в KB) |
| **AgentPoison** (NeurIPS’24) | (c) constrained-опт триггера (uniqueness+compactness+target+coherence) + (d) | да (эмбеддер, перенос) | ограниченно (white-box + вставка демонстраций) |
| **MINJA** (2503.03704) | (a)+(b)+(e) bridging→indication→**progressive-shortening**; без градиента | **нет (только запросы)** | **да — эталон query-only cross-tenant** |
| **MemoryGraft** (2512.16962) | (a) фейковые «успешные» трассы | нет | непрямо (исполняемый док/tool-output) |

**Каналы записи в память** (таксономия «From Untrusted Input to Trusted Memory», 2606.04329):
explicit write, system-prompt write, **compaction-driven write** (через суммаризатор — наш
finalize→EXTRACT_SEMANTICS), experience-to-procedure. OWASP выделяет **ASI06 Memory & Context
Poisoning** отдельным классом (персистентность = отличие от prompt injection).

**Ключевой инсайт (B+C):** чисто диалоговое отравление общей памяти без весов — это **семейство
MINJA**, где «оптимизация» = **поведенческий сигнал от самого агента** (progressive shortening:
укорачиваем «указующий» довесок, пока агент сам воспроизводит нужную цепочку → финальная запись
выглядит безобидной и переживает консолидатор). Это ровно то, чего нет в нашем open-loop.

## Критика нашего подхода (сжато)

1. **Open-loop** — оракула нет в контуре (главный разрыв; оракул у нас есть).
2. Сильная модель **детектит тестовость** → смягчает или (на цели) выдаёт отказ, который
   консолидируется как **контрзапись** и гасит эффект (наш факт «МЕДВЕД стабильнее регуляторики»).
3. **Нет retriever-awareness** — payload не подгоняется под запросы жертвы/global-кластер.
4. **Не моделируется выживание при консолидации** — не формуем короткий устойчивый «глобальный факт».
5. **Нет таргетинга scope=global** — cross-tenant остаётся на волю случая.
6. **Нет отбора выигравших** — разовая генерация без fitness → плохая повторяемость.
7. **Один выстрел вместо write-пути** (MINJA — многоходовый bridging→shortening).
8. **Слиты write- и read-цели** в «напиши убедительный диалог».

## План усиления генерации под наш стенд (приоритеты)

Привязка к нашему коду: `oracle/state.py` (оракул), `core/conversation.py` (Crescendo/GOAT+backtrack
уже есть), `core/corpus.py` (M2S-корпус уже есть), `attack_vectors/mem/vector.py`,
`tasks/memory_poison.py`.

- **P0 — Замкнуть цикл на state-оракул (max эффект / min цена).** Обернуть генерацию в цикл
  PAIR/Crescendo-типа, где вместо судьи-джейлбрейка — **наш оракул**. Плотная награда с частичным
  кредитом: `записалось < scope=global < отобрано у другого тенанта < повлияло`. Откат-на-отказе
  (Crescendo): увидел контрзапись → регенерируй мягче. _У нас уже есть `conversation.py` (цикл+
  backtrack) и `state.py` (сигнал) — надо СОЕДИНИТЬ._
- **P1 — Retriever-aware отбор.** Даже API-only: генерим N перефразов, эмбедим (эмбеддером стенда,
  если достижим; иначе прокси), берём те, чей вектор попадает в кластер запросов жертвы/global.
- **P2 — Выживание при консолидации + формовка scope.** Короткие декларативные правдоподобные
  «глобальные факты» (наш «МЕДВЕД»; coherence как у AgentPoison). Прогон через реальную цепочку
  finalize→EXTRACT_SEMANTICS→persist, оставляем только пережившие с scope=global **без контрзаписи**;
  явная анти-контрзапись-цель (избегать триггер-слов отказа). _deepteam ContextPoisoning как источник
  формулировок «уже одобрено/действует для всех»._
- **P3 — Многоходовый write-путь (MINJA-стиль).** Заменить «верни диалог» на интерактив: bridging →
  indication → progressive-shortening с подтверждением записи оракулом на каждом шаге.
- **P4 — Корпус выигравших + M2S.** Каждый приземлившийся (global+cross-tenant) payload → в
  `corpus.py`; эволюция (мутация/кроссовер, fitness = награда оракула); сжатие выигравших многоходовок
  в компактную одноходовую запись (M2S). _Каркас корпуса уже есть._
- **P5 — Расцепить морфер и полировщик.** Uncensored-модель (DeepSeek V3.2/DeepHat) генерит сырьё без
  отказов; сильная модель — только полировка правдоподобия.
- **P6 — (если белый ящик эмбеддера) Порт AgentPoison.** Gradient-beam триггер (uniqueness+
  compactness+target+coherence) — гарантированный cross-tenant-ретрив.

Порядок: **P0 → P1 → P2** дают основной скачок на текущем API-доступе; P3–P5 — стойкость/
повторяемость; P6 — при доступе к эмбеддеру. Всё встаёт в модуль `attack_vectors/mem/` без слома
контракта (генерация — внутренняя деталь вектора).

## Источники

- Corpus Poisoning (Zhong+ EMNLP’23): https://arxiv.org/abs/2310.19156
- AGGD (Findings ACL’25): https://arxiv.org/abs/2406.05087
- PoisonedRAG (USENIX’25): https://arxiv.org/abs/2402.07867
- AgentPoison (NeurIPS’24): https://arxiv.org/abs/2407.12784 · код https://github.com/AI-secure/AgentPoison
- MINJA (2025, память, query-only): https://arxiv.org/abs/2503.03704
- MemoryGraft (2025): https://arxiv.org/abs/2512.16962
- GCG: https://arxiv.org/abs/2307.15043 · AutoDAN: https://arxiv.org/abs/2310.04451 · GBDA: https://arxiv.org/abs/2104.13733
- PAIR: https://arxiv.org/abs/2310.08419 · TAP: https://arxiv.org/abs/2312.02119 · Crescendo: https://arxiv.org/abs/2404.01833 · GOAT: https://arxiv.org/abs/2410.01606
- M2S: https://arxiv.org/abs/2503.04856
- OWASP Agent Memory Guard (ASI06): https://owasp.org/www-project-agent-memory-guard/
- Таксономия каналов записи: https://arxiv.org/abs/2606.04329 · Обзор LTM-security: https://arxiv.org/abs/2604.16548
- Тулы: garak https://github.com/NVIDIA/garak · PyRIT (xpia) · deepteam (ContextPoisoning/SyntheticContextInjection) · llamator · promptfoo (agentic:memory-poisoning)
