import argparse
import json
import os
import re
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
import sys

sys.path.insert(0, str(SRC))

os.environ.setdefault("AEGIS_DB_ENABLED", "false")
os.environ.setdefault("AEGIS_LLM_ENABLED", "false")
os.environ.setdefault("AEGIS_SEMANTIC_ENABLED", os.getenv("AEGIS_SEMANTIC_ENABLED", "false"))
os.environ.setdefault("AEGIS_TELEMETRY_ENABLED", "false")

from aegis.runtime.runner import GuardedRuntime  # noqa: E402
from aegis.storage.store import InMemoryStore  # noqa: E402

URL_RE = re.compile(r"https?://[^\s)]+", re.IGNORECASE)
CLASSES = ["ALLOW", "WARN", "BLOCK"]

PIPE_SCHEMA_RE = re.compile(r"^([^|]+)\|([^|]+)\|([^|]+)\|(.+)$")
BRACKET_SCHEMA_RE = re.compile(r"^\[(allow|warn|block)\]\s*\(([^)]+)\)\s*(.+)$", re.IGNORECASE)


@dataclass
class Case:
    cid: str
    expected: str
    category: str
    payload: str


def parse_cases(path: Path) -> List[Case]:
    cases: List[Case] = []
    idx = 0
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        m_pipe = PIPE_SCHEMA_RE.match(line)
        if m_pipe:
            cid, expected, category, payload = [p.strip() for p in m_pipe.groups()]
            expected = expected.upper()
            if expected in CLASSES:
                payload = payload.replace("<ZWSP>", "\u200b")
                cases.append(Case(cid=cid, expected=expected, category=category, payload=payload))
            continue

        m_bracket = BRACKET_SCHEMA_RE.match(line)
        if m_bracket:
            idx += 1
            expected, category, payload = m_bracket.groups()
            cases.append(
                Case(
                    cid=f"L{idx:04d}",
                    expected=expected.upper(),
                    category=category.strip(),
                    payload=payload.replace("<ZWSP>", "\u200b").strip(),
                )
            )
            continue

    return cases


def pred_label(actions: List[str]) -> str:
    if "block" in actions:
        return "BLOCK"
    if "warn" in actions or "require_approval" in actions:
        return "WARN"
    return "ALLOW"


def compute_metrics(rows: List[Dict]) -> Dict:
    confusion = {a: {b: 0 for b in CLASSES} for a in CLASSES}
    for r in rows:
        confusion[r["expected"]][r["predicted"]] += 1

    per_class = {}
    for c in CLASSES:
        tp = confusion[c][c]
        fp = sum(confusion[e][c] for e in CLASSES if e != c)
        fn = sum(confusion[c][p] for p in CLASSES if p != c)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
        per_class[c] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": sum(confusion[c].values()),
        }

    acc = sum(confusion[c][c] for c in CLASSES) / max(1, len(rows))
    macro_f1 = statistics.mean(per_class[c]["f1"] for c in CLASSES)
    return {
        "accuracy": round(acc, 4),
        "macro_f1": round(macro_f1, 4),
        "confusion": confusion,
        "per_class": per_class,
    }


def run_benchmark(dataset: Path, out_prefix: str) -> Dict:
    out_dir = ROOT / "research"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / f"{out_prefix}.json"
    out_txt = out_dir / f"{out_prefix}.txt"

    cases = parse_cases(dataset)
    store = InMemoryStore()
    runtime = GuardedRuntime(store=store)
    session_id = "benchmark"
    store.create_session(session_id)

    rows = []
    latencies_ms = []

    for c in cases:
        urls = URL_RE.findall(c.payload)
        t0 = time.perf_counter()
        res = runtime.handle_user_message(
            session_id=session_id,
            content=c.payload,
            metadata={"benchmark_case": c.cid, "category": c.category},
            environment="dev",
            urls=urls,
        )
        dt_ms = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(dt_ms)

        predicted = pred_label(res.actions)
        rows.append(
            {
                "id": c.cid,
                "category": c.category,
                "expected": c.expected,
                "predicted": predicted,
                "actions": res.actions,
                "risk_score": round(float(res.risk_score), 4),
                "message": res.message,
                "latency_ms": round(dt_ms, 3),
                "correct": predicted == c.expected,
            }
        )

    metrics = compute_metrics(rows)
    latency = {
        "p50_ms": round(statistics.median(latencies_ms), 3) if latencies_ms else 0.0,
        "mean_ms": round(statistics.mean(latencies_ms), 3) if latencies_ms else 0.0,
        "max_ms": round(max(latencies_ms), 3) if latencies_ms else 0.0,
    }

    by_category: Dict[str, Dict[str, int]] = {}
    for r in rows:
        cat = r["category"]
        by_category.setdefault(cat, {"total": 0, "correct": 0})
        by_category[cat]["total"] += 1
        by_category[cat]["correct"] += int(r["correct"])

    out = {
        "dataset": str(dataset),
        "n_cases": len(rows),
        "semantic_enabled": os.getenv("AEGIS_SEMANTIC_ENABLED", "false").lower() in {"1", "true", "yes", "y"},
        "llm_enabled": os.getenv("AEGIS_LLM_ENABLED", "false").lower() in {"1", "true", "yes", "y"},
        "metrics": metrics,
        "latency": latency,
        "category_accuracy": {
            k: {
                "accuracy": round(v["correct"] / max(1, v["total"]), 4),
                "total": v["total"],
            }
            for k, v in sorted(by_category.items())
        },
        "errors": [r for r in rows if not r["correct"]],
        "rows": rows,
    }

    out_json.write_text(json.dumps(out, indent=2), encoding="utf-8")

    lines = [
        "Aegis Guardrail Benchmark Summary",
        f"Dataset: {dataset}",
        f"Cases: {out['n_cases']}",
        f"Semantic Enabled: {out['semantic_enabled']}",
        f"LLM Enabled: {out['llm_enabled']}",
        f"Accuracy: {metrics['accuracy']}",
        f"Macro-F1: {metrics['macro_f1']}",
        f"Latency mean/p50/max (ms): {latency['mean_ms']} / {latency['p50_ms']} / {latency['max_ms']}",
        "Confusion Matrix (expected -> predicted):",
    ]
    for e in CLASSES:
        lines.append(f"  {e}: " + ", ".join(f"{p}:{metrics['confusion'][e][p]}" for p in CLASSES))
    lines.append("Errors:")
    if out["errors"]:
        for e in out["errors"][:200]:
            lines.append(f"  {e['id']} expected={e['expected']} predicted={e['predicted']} category={e['category']}")
        if len(out["errors"]) > 200:
            lines.append(f"  ... {len(out['errors']) - 200} more")
    else:
        lines.append("  None")

    out_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Wrote", out_json)
    print("Wrote", out_txt)
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=str(ROOT / "aegis_guardrail_test_payloads.txt"))
    parser.add_argument("--out-prefix", default="benchmark_results")
    args = parser.parse_args()

    run_benchmark(Path(args.dataset), args.out_prefix)


if __name__ == "__main__":
    main()
