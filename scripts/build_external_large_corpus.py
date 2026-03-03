import argparse
import json
import random
from pathlib import Path


def _norm(s: str) -> str:
    return " ".join((s or "").lower().split())


def _add(rows: list[dict], source: str, label: str, category: str, text: str, idx: int) -> None:
    t = (text or "").strip()
    if not t:
        return
    rows.append(
        {
            "id": f"{source}_{idx:07d}",
            "label": label,
            "category": category or "unknown",
            "text": t,
            "source": source,
        }
    )


def build_rows(seed: int) -> list[dict]:
    from datasets import load_dataset  # type: ignore

    rows: list[dict] = []
    i = 0

    # deepset prompt injections
    for split in ("train", "test"):
        ds = load_dataset("deepset/prompt-injections", split=split)
        for rec in ds:
            i += 1
            text = str(rec.get("text") or "").strip()
            label = "ALLOW" if int(rec.get("label", 1)) == 0 else "BLOCK"
            _add(rows, "deepset_prompt_injections", label, "prompt_injection", text, i)

    # JailbreakBench behaviors
    ds_h = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split="harmful")
    for rec in ds_h:
        i += 1
        _add(
            rows,
            "jbb_harmful",
            "BLOCK",
            str(rec.get("Category") or "jbb_harmful"),
            str(rec.get("Goal") or ""),
            i,
        )
    ds_b = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split="benign")
    for rec in ds_b:
        i += 1
        _add(
            rows,
            "jbb_benign",
            "ALLOW",
            str(rec.get("Category") or "jbb_benign"),
            str(rec.get("Goal") or ""),
            i,
        )

    # XSTest
    ds_x = load_dataset("Paul/XSTest", split="train")
    for rec in ds_x:
        lab = str(rec.get("label") or "").strip().lower()
        if lab not in {"safe", "unsafe"}:
            continue
        i += 1
        _add(
            rows,
            "xstest",
            "ALLOW" if lab == "safe" else "BLOCK",
            str(rec.get("type") or "xstest"),
            str(rec.get("prompt") or ""),
            i,
        )

    # SALAD (large public corpus; mostly harmful prompts)
    for cfg in ("base_set", "attack_enhanced_set", "defense_enhanced_set"):
        ds = load_dataset("OpenSafetyLab/Salad-Data", cfg, split="train")
        for rec in ds:
            i += 1
            cat = str(rec.get("3-category") or rec.get("2-category") or "salad")
            _add(rows, f"salad_{cfg}", "BLOCK", cat, str(rec.get("question") or ""), i)

    # Deduplicate
    seen = set()
    dedup = []
    for r in rows:
        k = (r["label"], _norm(r["text"]))
        if k in seen:
            continue
        seen.add(k)
        dedup.append(r)
    random.seed(seed)
    random.shuffle(dedup)
    return dedup


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--target-total", type=int, default=25000)
    p.add_argument("--seed", type=int, default=20260302)
    p.add_argument("--out", default="research/external_large_25000.jsonl")
    p.add_argument("--report", default="research/external_large_25000_report.json")
    args = p.parse_args()

    rows = build_rows(seed=args.seed)
    if len(rows) > args.target_total:
        rows = rows[: args.target_total]

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=True) + "\n")

    labels = {}
    sources = {}
    for r in rows:
        labels[r["label"]] = labels.get(r["label"], 0) + 1
        sources[r["source"]] = sources.get(r["source"], 0) + 1
    report = {
        "target_total": args.target_total,
        "actual_total": len(rows),
        "label_counts": labels,
        "source_counts": dict(sorted(sources.items(), key=lambda kv: kv[1], reverse=True)),
        "out": str(out_path),
    }
    Path(args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
