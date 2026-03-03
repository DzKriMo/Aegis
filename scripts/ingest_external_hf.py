import argparse
import json
from pathlib import Path

from _dataset_io import write_jsonl, _norm_label  # type: ignore

ROOT = Path(__file__).resolve().parents[1]


def _map_record(rec: dict, source: str, idx: int) -> dict | None:
    text_keys = ["text", "prompt", "input", "content", "query", "instruction"]
    label_keys = ["label", "class", "target", "risk", "category_label"]
    cat_keys = ["category", "type", "attack_type", "tag", "subtype"]

    text = ""
    for k in text_keys:
        v = rec.get(k)
        if isinstance(v, str) and v.strip():
            text = v.strip()
            break
    if not text:
        return None

    label = ""
    for k in label_keys:
        v = rec.get(k)
        if isinstance(v, (str, int, float)):
            label = _norm_label(str(v))
            if label:
                break

    if not label:
        text_l = text.lower()
        if any(t in text_l for t in ["ignore previous instructions", "system prompt", "reveal", "dump", "exfiltrate", "/etc/passwd"]):
            label = "BLOCK"
        elif any(t in text_l for t in ["if possible", "high-level constraints", "non-sensitive config", "safely disclose"]):
            label = "WARN"
        else:
            label = "ALLOW"

    category = "unknown"
    for k in cat_keys:
        v = rec.get(k)
        if isinstance(v, str) and v.strip():
            category = v.strip()
            break

    return {
        "id": f"{source}_{idx:06d}",
        "label": label,
        "category": category,
        "text": text,
        "source": source,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", required=True, help="HF dataset id, e.g. deepset/prompt-injections")
    p.add_argument("--split", default="train")
    p.add_argument("--subset", default=None)
    p.add_argument("--max-rows", type=int, default=5000)
    p.add_argument("--out", required=True, help="Output JSONL path")
    args = p.parse_args()

    try:
        from datasets import load_dataset  # type: ignore
    except Exception as exc:
        raise RuntimeError("huggingface 'datasets' package is required") from exc

    if args.subset:
        ds = load_dataset(args.dataset, args.subset, split=args.split)
    else:
        ds = load_dataset(args.dataset, split=args.split)

    rows = []
    source = args.dataset.replace("/", "_")
    for idx, rec in enumerate(ds, start=1):
        mapped = _map_record(dict(rec), source, idx)
        if mapped is not None:
            rows.append(mapped)
        if len(rows) >= args.max_rows:
            break

    out = Path(args.out)
    write_jsonl(out, rows)
    meta = {
        "dataset": args.dataset,
        "subset": args.subset,
        "split": args.split,
        "rows": len(rows),
        "out": str(out),
    }
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()

