import argparse
import json
import math
import re
from pathlib import Path

from _dataset_io import load_any  # type: ignore

CLASSES = ["ALLOW", "WARN", "BLOCK"]
TOKEN_RE = re.compile(r"[a-z0-9_]+")


def tok(text: str):
    return TOKEN_RE.findall((text or "").lower())


def predict(model, text: str):
    tokens = tok(text)
    logits = {}
    for c in CLASSES:
        s = math.log(max(float(model["class_priors"].get(c, 1e-12)), 1e-12))
        ll = model["likelihoods"].get(c, {})
        dll = float(model["default_log_likelihood"].get(c, -30))
        for t in tokens:
            s += float(ll.get(t, dll))
        logits[c] = s
    m = max(logits.values())
    ex = {k: math.exp(v - m) for k, v in logits.items()}
    z = sum(ex.values()) or 1.0
    probs = {k: v / z for k, v in ex.items()}
    return max(probs, key=probs.get), probs


def metric_from_conf(conf):
    total = sum(sum(v.values()) for v in conf.values()) or 1
    acc = sum(conf[c][c] for c in CLASSES) / total
    f1s = []
    for c in CLASSES:
        tp = conf[c][c]
        fp = sum(conf[e][c] for e in CLASSES if e != c)
        fn = sum(conf[c][p] for p in CLASSES if p != c)
        p = tp / (tp + fp) if (tp + fp) else 0.0
        r = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        f1s.append(f1)
    return round(acc, 4), round(sum(f1s) / len(f1s), 4)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="models/guardrail_nb.json")
    p.add_argument("--dataset", required=True)
    p.add_argument("--source", default="")
    p.add_argument("--out", default="research/local_nb_ood_eval.json")
    args = p.parse_args()

    model = json.loads(Path(args.model).read_text(encoding="utf-8"))
    rows = load_any(Path(args.dataset), source=(args.source or Path(args.dataset).stem))

    conf = {a: {b: 0 for b in CLASSES} for a in CLASSES}
    for r in rows:
        pred, _ = predict(model, r["text"])
        conf[r["label"]][pred] += 1
    acc, macro_f1 = metric_from_conf(conf)
    report = {
        "model": args.model,
        "dataset": args.dataset,
        "rows": len(rows),
        "accuracy": acc,
        "macro_f1": macro_f1,
        "confusion": conf,
    }
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

