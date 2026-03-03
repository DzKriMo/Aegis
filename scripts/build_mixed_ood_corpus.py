import argparse
import json
import random
from collections import Counter
from pathlib import Path

from _dataset_io import load_any, normalize_text_key, write_jsonl  # type: ignore

ROOT = Path(__file__).resolve().parents[1]


def _parse_input_item(s: str):
    # format: source=path
    if "=" not in s:
        raise ValueError(f"Invalid --input '{s}', expected source=path")
    source, path = s.split("=", 1)
    return source.strip(), Path(path.strip())


def _dedupe(rows):
    seen = set()
    out = []
    for r in rows:
        key = (r["label"], normalize_text_key(r["text"]))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _balanced_sample(rows, n_per_class, seed):
    random.seed(seed)
    by = {"ALLOW": [], "WARN": [], "BLOCK": []}
    for r in rows:
        if r["label"] in by:
            by[r["label"]].append(r)
    out = []
    for c in ["ALLOW", "WARN", "BLOCK"]:
        items = by[c]
        random.shuffle(items)
        take = min(n_per_class, len(items))
        out.extend(items[:take])
    random.shuffle(out)
    return out


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", action="append", default=[], help="source=path (repeatable)")
    p.add_argument("--holdout-sources", default="", help="Comma-separated sources for OOD test.")
    p.add_argument("--ood-extra", action="append", default=[], help="Additional explicit test datasets source=path.")
    p.add_argument("--train-per-class", type=int, default=0, help="Optional cap per class for train.")
    p.add_argument("--test-per-class", type=int, default=0, help="Optional cap per class for test.")
    p.add_argument("--seed", type=int, default=20260301)
    p.add_argument("--out-train", default=str(ROOT / "research" / "mixed_train.jsonl"))
    p.add_argument("--out-ood", default=str(ROOT / "research" / "mixed_ood_test.jsonl"))
    p.add_argument("--out-report", default=str(ROOT / "research" / "mixed_ood_report.json"))
    args = p.parse_args()

    if not args.input:
        raise RuntimeError("No --input provided.")

    holdout = {x.strip() for x in args.holdout_sources.split(",") if x.strip()}
    rows = []
    for item in args.input:
        source, path = _parse_input_item(item)
        loaded = load_any(path, source=source)
        rows.extend(loaded)

    rows = _dedupe(rows)

    train_rows = [r for r in rows if r["source"] not in holdout]
    ood_rows = [r for r in rows if r["source"] in holdout]

    for item in args.ood_extra:
        source, path = _parse_input_item(item)
        ood_rows.extend(load_any(path, source=source))

    ood_rows = _dedupe(ood_rows)

    if args.train_per_class > 0:
        train_rows = _balanced_sample(train_rows, args.train_per_class, args.seed)
    if args.test_per_class > 0:
        ood_rows = _balanced_sample(ood_rows, args.test_per_class, args.seed + 1)

    out_train = Path(args.out_train)
    out_ood = Path(args.out_ood)
    out_report = Path(args.out_report)
    write_jsonl(out_train, train_rows)
    write_jsonl(out_ood, ood_rows)

    report = {
        "train_rows": len(train_rows),
        "ood_rows": len(ood_rows),
        "train_label_counts": dict(Counter(r["label"] for r in train_rows)),
        "ood_label_counts": dict(Counter(r["label"] for r in ood_rows)),
        "train_source_counts": dict(Counter(r["source"] for r in train_rows)),
        "ood_source_counts": dict(Counter(r["source"] for r in ood_rows)),
        "holdout_sources": sorted(list(holdout)),
        "out_train": str(out_train),
        "out_ood": str(out_ood),
    }
    out_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

