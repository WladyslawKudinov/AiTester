#!/usr/bin/env python3
"""Точка входа проекта (source-layout).

Запуск из корня:  ./.venv/bin/python run.py <cmd> [--attempts N] [--no-llm] [--marker X]
Команды: smoke | bac | poison | chain | models | mem | repro | all

Кладёт source/ в путь импорта и передаёт управление CLI харнесса (source/harness/orchestration/run.py).
Код — в source/, документация — в docs/, прогоны и артефакты — в output/.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "source"))

from harness.orchestration.run import main  # noqa: E402

raise SystemExit(main())
