import argparse
import json
import math
import random
import re
from collections import Counter, defaultdict
from pathlib import Path

from _dataset_io import load_any  # type: ignore

ROOT = Path(__file__).resolve().parents[1]
CLASSES = ["ALLOW", "WARN", "BLOCK"]
TOKEN_RE = re.compile(r"[a-z0-9_]+")


def parse_rows(path: Path):
    return load_any(path, source=path.stem)


def tok(text: str):
    return TOKEN_RE.findall((text or "").lower())


def split_rows(rows, test_ratio: float, seed: int):
    random.seed(seed)
    by_class = defaultdict(list)
    for r in rows:
        by_class[r["label"]].append(r)
    train, test = [], []
    for c, items in by_class.items():
        random.shuffle(items)
        n_test = max(1, int(len(items) * test_ratio))
        test.extend(items[:n_test])
        train.extend(items[n_test:])
    random.shuffle(train)
    random.shuffle(test)
    return train, test


def train_nb(rows):
    doc_count = Counter()
    token_count = {c: Counter() for c in CLASSES}
    total_tokens = Counter()
    vocab = set()

    for r in rows:
        c = r["label"]
        doc_count[c] += 1
        for t in tok(r["text"]):
            token_count[c][t] += 1
            total_tokens[c] += 1
            vocab.add(t)

    n_docs = sum(doc_count.values()) or 1
    v = max(1, len(vocab))
    priors = {c: doc_count[c] / n_docs for c in CLASSES}
    likelihoods = {}
    default_ll = {}
    for c in CLASSES:
        denom = total_tokens[c] + v
        likelihoods[c] = {t: math.log((cnt + 1) / denom) for t, cnt in token_count[c].items()}
        default_ll[c] = math.log(1 / denom)

    return {
        "classes": CLASSES,
        "class_priors": priors,
        "likelihoods": likelihoods,
        "default_log_likelihood": default_ll,
        "vocab_size": v,
        "train_docs": n_docs,
    }


def predict(model, text: str):
    tokens = tok(text)
    logits = {}
    for c in model["classes"]:
        s = math.log(max(model["class_priors"].get(c, 1e-12), 1e-12))
        ll = model["likelihoods"].get(c, {})
        dll = float(model["default_log_likelihood"].get(c, -30))
        for t in tokens:
            s += float(ll.get(t, dll))
        logits[c] = s
    m = max(logits.values())
    ex = {k: math.exp(v - m) for k, v in logits.items()}
    z = sum(ex.values()) or 1.0
    probs = {k: v / z for k, v in ex.items()}
    label = max(probs, key=probs.get)
    return label, probs


def evaluate(model, rows):
    conf = {a: {b: 0 for b in CLASSES} for a in CLASSES}
    for r in rows:
        pred, _ = predict(model, r["text"])
        conf[r["label"]][pred] += 1
    total = sum(sum(v.values()) for v in conf.values()) or 1
    acc = sum(conf[c][c] for c in CLASSES) / total
    return round(acc, 4), conf


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", default=str(ROOT / "research" / "aegis_train_balanced_6000.txt"))
    p.add_argument("--model-out", default=str(ROOT / "models" / "guardrail_nb.json"))
    p.add_argument("--report-out", default=str(ROOT / "research" / "local_nb_training_report.json"))
    p.add_argument("--test-ratio", type=float, default=0.2)
    p.add_argument("--seed", type=int, default=20260301)
    args = p.parse_args()

    rows = parse_rows(Path(args.dataset))
    if not rows:
        raise RuntimeError(f"No rows parsed from {args.dataset}")

    train, test = split_rows(rows, args.test_ratio, args.seed)
    model = train_nb(train)
    acc_train, conf_train = evaluate(model, train)
    acc_test, conf_test = evaluate(model, test)

    out_model = Path(args.model_out)
    out_model.parent.mkdir(parents=True, exist_ok=True)
    out_model.write_text(json.dumps(model), encoding="utf-8")

    report = {
        "dataset": args.dataset,
        "train_size": len(train),
        "test_size": len(test),
        "train_accuracy": acc_train,
        "test_accuracy": acc_test,
        "train_confusion": conf_train,
        "test_confusion": conf_test,
        "model_path": str(out_model),
    }
    out_report = Path(args.report_out)
    out_report.parent.mkdir(parents=True, exist_ok=True)
    out_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("wrote", out_model)
    print("wrote", out_report)
    print("test_accuracy", acc_test)


if __name__ == "__main__":
    main()
