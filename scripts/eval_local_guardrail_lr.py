import argparse
import json
from pathlib import Path

import joblib  # type: ignore
from sklearn.metrics import confusion_matrix, f1_score  # type: ignore

from _dataset_io import load_any  # type: ignore

CLASSES = ["ALLOW", "WARN", "BLOCK"]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="models/guardrail_lr.joblib")
    p.add_argument("--dataset", required=True)
    p.add_argument("--source", default="")
    p.add_argument("--out", default="research/local_lr_eval.json")
    args = p.parse_args()

    model = joblib.load(Path(args.model))
    pipeline = model.get("pipeline") if isinstance(model, dict) else model

    rows = load_any(Path(args.dataset), source=(args.source or Path(args.dataset).stem))
    rows = [r for r in rows if r.get("text") and r.get("label") in CLASSES]
    x = [r["text"] for r in rows]
    y = [r["label"] for r in rows]

    pred = list(pipeline.predict(x))
    correct = sum(1 for a, b in zip(y, pred) if a == b)
    acc = round(correct / max(1, len(y)), 4)
    macro_f1 = round(float(f1_score(y, pred, labels=CLASSES, average="macro", zero_division=0)), 4)
    cm = confusion_matrix(y, pred, labels=CLASSES).tolist()
    out = {
        "model": args.model,
        "dataset": args.dataset,
        "rows": len(rows),
        "accuracy": acc,
        "macro_f1": macro_f1,
        "labels": CLASSES,
        "confusion": cm,
    }
    Path(args.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
