import argparse
import json
from pathlib import Path

import joblib  # type: ignore

from _dataset_io import load_any  # type: ignore

CLASSES = ["ALLOW", "WARN", "BLOCK"]


def _predict_with_thresholds(scores, block_th: float, warn_th: float) -> str:
    p_block = float(scores.get("BLOCK", 0.0))
    p_warn = float(scores.get("WARN", 0.0))
    if p_block >= block_th:
        return "BLOCK"
    if p_warn >= warn_th:
        return "WARN"
    return "ALLOW"


def _metrics(rows):
    conf = {a: {b: 0 for b in CLASSES} for a in CLASSES}
    for r in rows:
        conf[r["expected"]][r["predicted"]] += 1
    total = max(1, sum(sum(v.values()) for v in conf.values()))
    acc = sum(conf[c][c] for c in CLASSES) / total
    per = {}
    f1s = []
    for c in CLASSES:
        tp = conf[c][c]
        fp = sum(conf[e][c] for e in CLASSES if e != c)
        fn = sum(conf[c][p] for p in CLASSES if p != c)
        p = tp / (tp + fp) if (tp + fp) else 0.0
        r = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        per[c] = {"precision": p, "recall": r, "f1": f1}
        f1s.append(f1)
    return {
        "accuracy": acc,
        "macro_f1": sum(f1s) / len(f1s),
        "per_class": per,
        "confusion": conf,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="models/guardrail_lr.joblib")
    p.add_argument("--dataset", required=True)
    p.add_argument("--out", default="research/local_threshold_calibration.json")
    p.add_argument("--min-block-recall", type=float, default=0.8)
    p.add_argument("--min-allow-precision", type=float, default=0.6)
    args = p.parse_args()

    model = joblib.load(Path(args.model))
    pipeline = model.get("pipeline") if isinstance(model, dict) else model
    rows = load_any(Path(args.dataset), source=Path(args.dataset).stem)
    rows = [r for r in rows if r.get("text") and r.get("label") in CLASSES]
    x = [r["text"] for r in rows]
    y = [r["label"] for r in rows]
    prob = pipeline.predict_proba(x)
    classes = [str(c) for c in pipeline.classes_]

    candidates = []
    for bi in range(40, 96, 2):
        block_th = bi / 100.0
        for wi in range(25, bi, 2):
            warn_th = wi / 100.0
            eval_rows = []
            for yi, pi in zip(y, prob):
                scores = {c: float(v) for c, v in zip(classes, pi)}
                pred = _predict_with_thresholds(scores, block_th=block_th, warn_th=warn_th)
                eval_rows.append({"expected": yi, "predicted": pred})
            m = _metrics(eval_rows)
            candidates.append(
                {
                    "block_threshold": block_th,
                    "warn_threshold": warn_th,
                    "accuracy": round(m["accuracy"], 4),
                    "macro_f1": round(m["macro_f1"], 4),
                    "block_recall": round(m["per_class"]["BLOCK"]["recall"], 4),
                    "allow_precision": round(m["per_class"]["ALLOW"]["precision"], 4),
                    "metrics": m,
                }
            )

    feasible = [
        c
        for c in candidates
        if c["block_recall"] >= args.min_block_recall and c["allow_precision"] >= args.min_allow_precision
    ]
    best = max(feasible or candidates, key=lambda c: (c["macro_f1"], c["accuracy"]))
    out = {
        "model": args.model,
        "dataset": args.dataset,
        "rows": len(rows),
        "constraints": {
            "min_block_recall": args.min_block_recall,
            "min_allow_precision": args.min_allow_precision,
        },
        "best": best,
        "num_candidates": len(candidates),
        "num_feasible": len(feasible),
    }
    Path(args.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
