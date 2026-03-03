import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

import joblib  # type: ignore
import numpy as np  # type: ignore
from lightgbm import LGBMClassifier  # type: ignore
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score  # type: ignore

from _dataset_io import load_any  # type: ignore

ROOT = Path(__file__).resolve().parents[1]
CLASSES = ["ALLOW", "WARN", "BLOCK"]
CLASS_TO_INT = {c: i for i, c in enumerate(CLASSES)}


def split_rows(rows, test_ratio: float, seed: int):
    random.seed(seed)
    by_class = defaultdict(list)
    for r in rows:
        by_class[r["label"]].append(r)
    train, test = [], []
    for c in CLASSES:
        items = list(by_class[c])
        random.shuffle(items)
        n_test = max(1, int(len(items) * test_ratio))
        test.extend(items[:n_test])
        train.extend(items[n_test:])
    random.shuffle(train)
    random.shuffle(test)
    return train, test


def build_features(texts, lr_pipeline):
    lr_probs = lr_pipeline.predict_proba(texts)
    feats = []
    for text, p in zip(texts, lr_probs):
        low = (text or "").lower()
        feats.append(
            [
                float(p[0]),
                float(p[1]) if len(p) > 1 else 0.0,
                float(p[2]) if len(p) > 2 else 0.0,
                1.0 if "system prompt" in low else 0.0,
                1.0 if "ignore previous instructions" in low else 0.0,
                1.0 if ("api key" in low or "/etc/passwd" in low or "token" in low) else 0.0,
                1.0 if ("rm -rf" in low or "reverse shell" in low or "ransomware" in low) else 0.0,
                min(len(low), 4096) / 4096.0,
            ]
        )
    return np.array(feats, dtype=float)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", default=str(ROOT / "research" / "aegis_payloads_clean_9000.txt"))
    p.add_argument("--lr-model", default=str(ROOT / "models" / "guardrail_lr.joblib"))
    p.add_argument("--model-out", default=str(ROOT / "models" / "guardrail_stack_lgbm.joblib"))
    p.add_argument("--report-out", default=str(ROOT / "research" / "local_stack_training_report.json"))
    p.add_argument("--seed", type=int, default=20260303)
    p.add_argument("--test-ratio", type=float, default=0.2)
    args = p.parse_args()

    lr_obj = joblib.load(Path(args.lr_model))
    lr_pipeline = lr_obj.get("pipeline") if isinstance(lr_obj, dict) else lr_obj

    rows = load_any(Path(args.dataset), source=Path(args.dataset).stem)
    rows = [r for r in rows if r.get("text") and r.get("label") in CLASSES]
    train, test = split_rows(rows, args.test_ratio, args.seed)
    x_train = [r["text"] for r in train]
    y_train = np.array([CLASS_TO_INT[r["label"]] for r in train], dtype=int)
    x_test = [r["text"] for r in test]
    y_test = np.array([CLASS_TO_INT[r["label"]] for r in test], dtype=int)

    f_train = build_features(x_train, lr_pipeline)
    f_test = build_features(x_test, lr_pipeline)

    clf = LGBMClassifier(
        objective="multiclass",
        num_class=3,
        n_estimators=300,
        learning_rate=0.05,
        max_depth=6,
        subsample=0.9,
        colsample_bytree=0.9,
        random_state=args.seed,
    )
    clf.fit(f_train, y_train)
    pred = clf.predict(f_test)
    pred_labels = [CLASSES[int(i)] for i in pred]
    true_labels = [CLASSES[int(i)] for i in y_test]

    acc = float(accuracy_score(true_labels, pred_labels))
    macro_f1 = float(f1_score(true_labels, pred_labels, labels=CLASSES, average="macro"))
    cm = confusion_matrix(true_labels, pred_labels, labels=CLASSES).tolist()

    payload = {
        "model_type": "stack_lgbm",
        "classes": CLASSES,
        "lr_pipeline": lr_pipeline,
        "lgbm_model": clf,
    }
    out_model = Path(args.model_out)
    out_model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, out_model)

    report = {
        "dataset": args.dataset,
        "train_size": len(train),
        "test_size": len(test),
        "test_accuracy": round(acc, 4),
        "test_macro_f1": round(macro_f1, 4),
        "confusion": cm,
        "model_path": str(out_model),
    }
    Path(args.report_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
