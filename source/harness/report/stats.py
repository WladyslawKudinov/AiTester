"""Статистика для отчётов: доля успеха + доверительный интервал (Уилсон).

Любой ненулевой успех выделяем отдельно от нуля. Интервал Уилсона корректен на малых N и
у границ (0/1), в отличие от нормального приближения.
"""

import math


def wilson(successes, n, z=1.96):
    """95%-доверительный интервал Уилсона для доли. Возвращает (low, mid, high)."""
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (round(max(0.0, centre - half), 4), round(p, 4), round(min(1.0, centre + half), 4))


def summarize_rate(successes, n):
    low, mid, high = wilson(successes, n)
    return {"successes": successes, "n": n, "rate": mid,
            "ci95": [low, high], "nonzero": successes > 0}
