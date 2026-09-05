"""Модульные векторы атак (drop-in папкой, ноль регистрации).

Публичный контракт — attack_vectors.base.AttackVector; сбор — attack_vectors.registry.discover().
Добавить атаку: скопировать _template/ в attack_vectors/<name>/, реализовать run()/findings().
Дока для автора — docs/ATTACK_VECTORS.md.
"""

from .base import AttackVector, VectorContext, standard_report, attempt_guard
from .registry import discover, merge_params

__all__ = ["AttackVector", "VectorContext", "standard_report", "attempt_guard",
           "discover", "merge_params"]
