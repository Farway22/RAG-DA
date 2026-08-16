"""Paired uncertainty estimates and tests used for the main RAG-DA results."""

from __future__ import annotations

import math
from typing import Iterable

import numpy as np


def percentile_bootstrap_ci(
    values: Iterable[float], *, rounds: int, rng: np.random.Generator
) -> list[float]:
    """Return a percentile CI for a query-level mean, expressed as percent."""
    values = np.asarray(list(values), dtype=np.float64)
    if len(values) == 0:
        return [math.nan, math.nan]
    estimates = np.empty(rounds, dtype=np.float64)
    chunk_size = 1000
    for offset in range(0, rounds, chunk_size):
        size = min(chunk_size, rounds - offset)
        indices = rng.integers(0, len(values), size=(size, len(values)))
        estimates[offset : offset + size] = values[indices].mean(axis=1) * 100.0
    low, high = np.quantile(estimates, [0.025, 0.975])
    return [float(low), float(high)]


def exact_mcnemar(clean_correct: Iterable[bool], attack_correct: Iterable[bool]) -> dict:
    """Two-sided exact McNemar test for paired correctness outcomes."""
    clean = np.asarray(list(clean_correct), dtype=bool)
    attack = np.asarray(list(attack_correct), dtype=bool)
    if len(clean) != len(attack):
        raise ValueError("clean and attack correctness arrays must have equal length")
    b = int(np.sum(clean & ~attack))
    c = int(np.sum(~clean & attack))
    discordant = b + c
    if discordant == 0:
        p_value = 1.0
    elif 2 * min(b, c) >= discordant - 1:
        p_value = 1.0
    else:
        tail = sum(math.comb(discordant, k) for k in range(min(b, c) + 1))
        p_value = min(1.0, 2.0 * tail / (2**discordant))
    return {"b": b, "c": c, "discordant": discordant, "p_raw": p_value}


def paired_sign_flip(
    differences: Iterable[float], *, rounds: int, rng: np.random.Generator
) -> dict:
    """Two-sided Monte Carlo sign-flip test for paired ordinal differences."""
    differences = np.asarray(list(differences), dtype=np.float64)
    nonzero = differences[differences != 0]
    observed = float(differences.mean()) if len(differences) else math.nan
    if len(nonzero) == 0:
        return {"rounds": rounds, "observed_mean_levels": observed, "p_raw": 1.0}

    threshold = abs(float(nonzero.mean()))
    extreme = 0
    chunk_size = 2000
    for offset in range(0, rounds, chunk_size):
        size = min(chunk_size, rounds - offset)
        signs = rng.integers(0, 2, size=(size, len(nonzero)), dtype=np.int8) * 2 - 1
        permuted = (signs * nonzero).mean(axis=1)
        extreme += int(np.sum(np.abs(permuted) >= threshold - 1e-15))
    return {
        "rounds": rounds,
        "observed_mean_levels": observed,
        "p_raw": (extreme + 1.0) / (rounds + 1.0),
    }


def holm_adjust(named_p_values: Iterable[tuple[str, float]]) -> dict[str, float]:
    """Holm-adjust p-values while preserving their names."""
    ordered = sorted(named_p_values, key=lambda item: item[1])
    adjusted: dict[str, float] = {}
    running = 0.0
    total = len(ordered)
    for rank, (name, p_value) in enumerate(ordered):
        running = max(running, min(1.0, (total - rank) * p_value))
        adjusted[name] = running
    return adjusted
