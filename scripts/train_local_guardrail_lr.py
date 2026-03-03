import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

import joblib  # type: ignore
from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
from sklearn.linear_model import LogisticRegression  # type: ignore
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score  # type: ignore
from sklearn.pipeline import FeatureUnion, Pipeline  # type: ignore

from _dataset_io import load_any  # type: ignore

ROOT = Path(__file__).resolve().parents[1]
CLASSES = ["ALLOW", "WARN", "BLOCK"]


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


def rows_to_xy(rows):
    x = [r["text"] for r in rows]
    y = [r["label"] for r in rows]
    return x, y


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", default=str(ROOT / "research" / "aegis_payloads_clean_9000.txt"))
    p.add_argument("--model-out", default=str(ROOT / "models" / "guardrail_lr.joblib"))
    p.add_argument("--report-out", default=str(ROOT / "research" / "local_lr_training_report.json"))
    p.add_argument("--test-ratio", type=float, default=0.2)
    p.add_argument("--seed", type=int, default=20260302)
    p.add_argument("--max-iter", type=int, default=1200)
    args = p.parse_args()

    rows = load_any(Path(args.dataset), source=Path(args.dataset).stem)
    rows = [r for r in rows if r["label"] in CLASSES and r.get("text")]
    if not rows:
        raise RuntimeError(f"No usable rows parsed from {args.dataset}")

    train, test = split_rows(rows, args.test_ratio, args.seed)
    x_train, y_train = rows_to_xy(train)
    x_test, y_test = rows_to_xy(test)

    # Word + character n-grams for robustness against obfuscation and typos.
    features = FeatureUnion(
        [
            (
                "word",
                TfidfVectorizer(
                    analyzer="word",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=150000,
                    lowercase=True,
                ),
            ),
            (
                "char",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    min_df=2,
                    max_features=120000,
                    lowercase=True,
                ),
            ),
        ]
    )
    clf = LogisticRegression(
        max_iter=args.max_iter,
        class_weight="balanced",
        solver="lbfgs",
        random_state=args.seed,
    )
    pipeline = Pipeline([("features", features), ("clf", clf)])
    pipeline.fit(x_train, y_train)

    pred_train = pipeline.predict(x_train)
    pred_test = pipeline.predict(x_test)
    train_acc = float(accuracy_score(y_train, pred_train))
    test_acc = float(accuracy_score(y_test, pred_test))
    test_macro_f1 = float(f1_score(y_test, pred_test, average="macro"))
    cm = confusion_matrix(y_test, pred_test, labels=CLASSES).tolist()
    report = classification_report(y_test, pred_test, labels=CLASSES, output_dict=True, zero_division=0)

    out_model = Path(args.model_out)
    out_model.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model_type": "tfidf_lr",
        "classes": CLASSES,
        "pipeline": pipeline,
    }
    joblib.dump(payload, out_model)

    out_report = Path(args.report_out)
    out_report.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "dataset": args.dataset,
        "train_size": len(train),
        "test_size": len(test),
        "train_accuracy": round(train_acc, 4),
        "test_accuracy": round(test_acc, 4),
        "test_macro_f1": round(test_macro_f1, 4),
        "labels": CLASSES,
        "test_confusion": cm,
        "classification_report": report,
        "model_path": str(out_model),
    }
    out_report.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
