import argparse
import json
from datetime import datetime
from pathlib import Path


def _extract_ts(path: Path) -> str:
    stem = path.stem
    for token in stem.split("_"):
        if len(token) == 8 and token.isdigit():
            return token
    return datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y%m%d")


def _load(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if "benchmark_mode" not in data:
        raise ValueError("not a benchmark result json")
    rel = data.get("reliability", {})
    return {
        "file": str(path),
        "ts": _extract_ts(path),
        "dataset": data.get("dataset"),
        "api_base": data.get("api_base"),
        "accuracy": float(data.get("metrics", {}).get("accuracy", 0.0)),
        "macro_f1": float(data.get("metrics", {}).get("macro_f1", 0.0)),
        "mean_ms": float(data.get("latency", {}).get("mean_ms", 0.0)),
        "availability_200": float(rel.get("availability_200", 0.0)) if rel else 0.0,
        "non_200": int(rel.get("non_200_count", 0)) if rel else 0,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--glob", default="research/benchmark_*.json")
    p.add_argument("--min-drop", type=float, default=0.03, help="Alert if accuracy drop exceeds this threshold.")
    p.add_argument("--out", default="research/benchmark_trend_report.json")
    args = p.parse_args()

    files = sorted(Path(".").glob(args.glob))
    rows = []
    for f in files:
        try:
            rows.append(_load(f))
        except Exception:
            continue
    rows.sort(key=lambda r: (r["dataset"] or "", r["ts"], r["file"]))

    alerts = []
    prev_by_dataset: dict[str, dict] = {}
    for r in rows:
        key = str(r["dataset"])
        prev = prev_by_dataset.get(key)
        if prev is not None:
            drop = prev["accuracy"] - r["accuracy"]
            if drop >= args.min_drop:
                alerts.append(
                    {
                        "dataset": key,
                        "prev_file": prev["file"],
                        "curr_file": r["file"],
                        "prev_accuracy": prev["accuracy"],
                        "curr_accuracy": r["accuracy"],
                        "drop": round(drop, 4),
                    }
                )
        prev_by_dataset[key] = r

    out = {
        "count": len(rows),
        "rows": rows,
        "alerts": alerts,
    }
    Path(args.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
