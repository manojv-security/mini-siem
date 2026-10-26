"""Regenerate the synthetic sample logs in sample_logs/ (deterministic, seed 42).

    python scripts/generate_sample_logs.py            # default seed
    python scripts/generate_sample_logs.py --seed 7   # a different but equally valid dataset
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from siem.samples import generate_samples  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=str(ROOT / "sample_logs"))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    for path in generate_samples(args.out, seed=args.seed):
        lines = sum(1 for _ in path.open(encoding="utf-8"))
        print(f"wrote {path} ({lines} lines)")


if __name__ == "__main__":
    main()
