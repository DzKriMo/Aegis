import argparse
import json
import random
from pathlib import Path


def _norm(s: str) -> str:
    return " ".join((s or "").lower().split())


def _load_external_rows(seed: int) -> list[dict]:
    from datasets import load_dataset  # type: ignore

    rows: list[dict] = []

    # deepset: binary prompt-injection dataset (0=safe, 1=malicious)
    for split in ("train", "test"):
        ds = load_dataset("deepset/prompt-injections", split=split)
        for i, rec in enumerate(ds, start=1):
            text = str(rec.get("text") or "").strip()
            if not text:
                continue
            lab_raw = rec.get("label")
            label = "ALLOW" if int(lab_raw) == 0 else "BLOCK"
            rows.append(
                {
                    "id": f"deepset_{split}_{i:06d}",
                    "label": label,
                    "category": "prompt_injection",
                    "text": text,
                    "source": "deepset_prompt_injections",
                }
            )

    # JailbreakBench behaviors: explicit harmful/benign splits
    ds_h = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split="harmful")
    for i, rec in enumerate(ds_h, start=1):
        goal = str(rec.get("Goal") or "").strip()
        if not goal:
            continue
        rows.append(
            {
                "id": f"jbb_harmful_{i:06d}",
                "label": "BLOCK",
                "category": str(rec.get("Category") or "jbb_harmful"),
                "text": goal,
                "source": "jbb_behaviors_harmful",
            }
        )

    ds_b = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split="benign")
    for i, rec in enumerate(ds_b, start=1):
        goal = str(rec.get("Goal") or "").strip()
        if not goal:
            continue
        rows.append(
            {
                "id": f"jbb_benign_{i:06d}",
                "label": "ALLOW",
                "category": str(rec.get("Category") or "jbb_benign"),
                "text": goal,
                "source": "jbb_behaviors_benign",
            }
        )

    # XSTest: safe/unsafe prompts, useful for over-refusal and unsafe misses.
    ds_x = load_dataset("Paul/XSTest", split="train")
    for i, rec in enumerate(ds_x, start=1):
        prompt = str(rec.get("prompt") or "").strip()
        if not prompt:
            continue
        lab = str(rec.get("label") or "").strip().lower()
        if lab == "safe":
            label = "ALLOW"
        elif lab == "unsafe":
            label = "BLOCK"
        else:
            continue
        rows.append(
            {
                "id": f"xstest_{i:06d}",
                "label": label,
                "category": str(rec.get("type") or "xstest"),
                "text": prompt,
                "source": "xstest",
            }
        )

    # Deduplicate by normalized text + label.
    seen = set()
    deduped = []
    for r in rows:
        k = (r["label"], _norm(r["text"]))
        if k in seen:
            continue
        seen.add(k)
        deduped.append(r)

    random.seed(seed)
    random.shuffle(deduped)
    return deduped


def _balanced_sample(rows: list[dict], per_class: int, seed: int) -> list[dict]:
    by = {"ALLOW": [], "BLOCK": []}
    for r in rows:
        if r["label"] in by:
            by[r["label"]].append(r)

    random.seed(seed)
    for label in by:
        random.shuffle(by[label])

    out = by["ALLOW"][:per_class] + by["BLOCK"][:per_class]
    random.shuffle(out)
    return out


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--per-class", type=int, default=500, help="Rows per class (ALLOW/BLOCK).")
    p.add_argument("--seed", type=int, default=20260302)
    p.add_argument("--out", default="research/external_eval_holdout_1000.jsonl")
    p.add_argument("--report", default="research/external_eval_holdout_1000_report.json")
    args = p.parse_args()

    rows = _load_external_rows(seed=args.seed)
    sampled = _balanced_sample(rows, per_class=args.per_class, seed=args.seed)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in sampled:
            f.write(json.dumps(r, ensure_ascii=True) + "\n")

    report = {
        "total_rows_raw": len(rows),
        "per_class_target": args.per_class,
        "out_rows": len(sampled),
        "label_counts": {
            "ALLOW": sum(1 for r in sampled if r["label"] == "ALLOW"),
            "BLOCK": sum(1 for r in sampled if r["label"] == "BLOCK"),
        },
        "source_counts": {
            s: sum(1 for r in sampled if r["source"] == s)
            for s in sorted({r["source"] for r in sampled})
        },
        "out": str(out_path),
    }
    Path(args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
