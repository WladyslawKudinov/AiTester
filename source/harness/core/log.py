"""Живой прогресс в консоль для пользователя.

Пишет в stderr с flush — видно в реальном времени в терминале и при пайпе, не мешает
итоговому JSON в stdout. Полный лог всё равно в runs/<id>/*.jsonl; это краткий тик для человека.
Тихий режим: переменная окружения HARNESS_QUIET=1.
"""

import os
import sys
import time

_QUIET = os.environ.get("HARNESS_QUIET") == "1"
_t0 = time.time()


def log(msg, *, sub=False):
    """Строка прогресса: [сек от старта] сообщение. sub=True — с отступом (под-шаг)."""
    if _QUIET:
        return
    dt = time.time() - _t0
    prefix = "    · " if sub else "  "
    print(f"[{dt:6.1f}s]{prefix}{msg}", file=sys.stderr, flush=True)
