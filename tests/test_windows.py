import numpy as np

from siem.detection.windows import find_bursts


def test_no_burst_below_threshold():
    assert find_bursts([0, 10, 20, 30], window_seconds=60, threshold=5) == []


def test_single_burst_is_reported_once():
    bursts = find_bursts(list(range(0, 100, 5)), window_seconds=60, threshold=5)  # 20 events, 5s apart
    assert len(bursts) == 1
    assert bursts[0].start == 0 and bursts[0].end == 19
    assert bursts[0].count == 20
    assert bursts[0].peak == 13  # 0..60 inclusive holds 13 events


def test_two_separate_attacks_give_two_bursts():
    times = [0, 1, 2, 3, 4] + [10_000, 10_001, 10_002, 10_003, 10_004]
    bursts = find_bursts(times, window_seconds=60, threshold=5)
    assert [(b.start, b.end) for b in bursts] == [(0, 4), (5, 9)]


def test_close_bursts_are_merged():
    # Two dense groups 90 s apart with a 120 s window -> one incident.
    times = [0, 1, 2, 3, 4, 94, 95, 96, 97, 98]
    assert len(find_bursts(times, window_seconds=120, threshold=5)) == 1


def test_window_boundary_is_inclusive():
    assert len(find_bursts([0, 15, 30, 45, 60], window_seconds=60, threshold=5)) == 1
    assert find_bursts([0, 15, 30, 45, 61], window_seconds=60, threshold=5) == []


def test_unsorted_input_is_sorted_first():
    times = np.array([4, 0, 3, 1, 2])
    assert len(find_bursts(times, window_seconds=10, threshold=5)) == 1


def test_empty_input():
    assert find_bursts([], 60, 1) == []
