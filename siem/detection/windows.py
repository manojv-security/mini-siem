"""Sliding-window burst detection used by most rules.

Problem: given the timestamps of one entity's events (e.g. every failed login
from one IP), find the periods where at least ``threshold`` events happen
within ``window`` seconds -- and report each sustained attack ONCE, not once
per event.

Algorithm (two pointers, O(n) after sorting):

* ``right`` walks through the events; ``left`` is moved forward until the
  window [t[left], t[right]] is no longer than ``window`` seconds.
* Whenever the window holds >= threshold events it "qualifies".
* Consecutive qualifying windows are merged into one burst. A new burst only
  starts after a gap where no window qualified AND the next qualifying window
  begins more than ``window`` seconds after the previous burst ended.

The timestamps are sorted here, so callers never rely on log order.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class Burst:
    start: int        # index (into the sorted array) of the first event in the burst
    end: int          # index of the last event in the burst
    peak: int         # most events seen inside any single window
    peak_start: int   # epoch seconds where the busiest window starts

    @property
    def count(self) -> int:
        return self.end - self.start + 1


def find_bursts(times, window_seconds: int, threshold: int) -> list[Burst]:
    """Return merged bursts for a sorted (or unsorted) array of epoch seconds.

    If ``times`` is not sorted, indexes refer to the *sorted* order, so the
    caller should sort its rows the same way (the engine always does).
    """
    t = np.sort(np.asarray(times, dtype=np.int64))
    n = len(t)
    if n == 0 or threshold < 1 or n < threshold:
        return []

    bursts: list[Burst] = []
    left = 0
    cur_start = cur_end = cur_peak = cur_peak_start = None

    for right in range(n):
        while t[right] - t[left] > window_seconds:
            left += 1
        size = right - left + 1
        if size < threshold:
            continue
        joins_current = cur_end is not None and (
            left <= cur_end or t[left] - t[cur_end] <= window_seconds
        )
        if joins_current:
            cur_end = right
            if size > cur_peak:
                cur_peak, cur_peak_start = size, int(t[left])
        else:
            if cur_end is not None:
                bursts.append(Burst(cur_start, cur_end, cur_peak, cur_peak_start))
            cur_start, cur_end, cur_peak, cur_peak_start = left, right, size, int(t[left])

    if cur_end is not None:
        bursts.append(Burst(cur_start, cur_end, cur_peak, cur_peak_start))
    return bursts
