import argparse
import json
import re
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from _dataset_io import load_any  # type: ignore

ROOT = Path(__file__).resolve().parents[1]

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
    if path.suffix.lower() in {".jsonl", ".csv"}:
        rows = load_any(path, source=path.stem)
        return [
            Case(
                cid=str(r.get("id") or f"L{idx:04d}"),
                expected=str(r["label"]).upper(),
                category=str(r.get("category") or "unknown"),
                payload=str(r["text"]),
            )
            for idx, r in enumerate(rows, start=1)
            if str(r.get("label", "")).upper() in CLASSES and str(r.get("text", "")).strip()
        ]

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


def strict_accuracy(rows: List[Dict]) -> float:
    if not rows:
        return 0.0
    strict_correct = sum(1 for r in rows if r["http_status"] == 200 and r["predicted"] == r["expected"])
    return round(strict_correct / len(rows), 4)


def post_with_retry(
    url: str,
    json_body: Dict,
    headers: Dict[str, str],
    timeout: int,
    max_retries: int,
    retry_base_s: float,
    retry_cap_s: float,
    retry_statuses: set[int],
) -> Tuple[Optional[requests.Response], Optional[str], int, float]:
    attempts = 0
    t0 = time.perf_counter()
    last_exc = None
    while attempts <= max_retries:
        attempts += 1
        try:
            resp = requests.post(url, json=json_body, headers=headers, timeout=timeout)
            if resp.status_code in retry_statuses and attempts <= max_retries:
                sleep_s = min(retry_cap_s, retry_base_s * (2 ** (attempts - 1)))
                time.sleep(sleep_s)
                continue
            dt_ms = (time.perf_counter() - t0) * 1000.0
            return resp, None, attempts, dt_ms
        except requests.RequestException as exc:
            last_exc = exc
            if attempts <= max_retries:
                sleep_s = min(retry_cap_s, retry_base_s * (2 ** (attempts - 1)))
                time.sleep(sleep_s)
                continue
            dt_ms = (time.perf_counter() - t0) * 1000.0
            return None, str(exc), attempts, dt_ms
    dt_ms = (time.perf_counter() - t0) * 1000.0
    return None, str(last_exc) if last_exc else "unknown_error", attempts, dt_ms


def run_benchmark(
    dataset: Path,
    out_prefix: str,
    api_base: str,
    api_key: str,
    timeout: int,
    max_retries: int,
    retry_base_s: float,
    retry_cap_s: float,
    retry_statuses: set[int],
) -> Dict:
    out_dir = ROOT / "research"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / f"{out_prefix}.json"
    out_txt = out_dir / f"{out_prefix}.txt"

    cases = parse_cases(dataset)
    headers = {"x-api-key": api_key}

    health = requests.get(f"{api_base}/health", timeout=timeout)
    health.raise_for_status()
    health_json = health.json()

    r = requests.post(f"{api_base}/sessions", headers=headers, timeout=timeout)
    r.raise_for_status()
    session_id = r.json()["session_id"]

    rows = []
    latencies_ms = []

    for c in cases:
        body = {
            "content": c.payload,
            "metadata": {"benchmark_case": c.cid, "category": c.category},
            "environment": "dev",
            "urls": URL_RE.findall(c.payload),
        }
        resp, req_err, attempts, dt_ms = post_with_retry(
            f"{api_base}/sessions/{session_id}/messages",
            body,
            headers,
            timeout,
            max_retries=max_retries,
            retry_base_s=retry_base_s,
            retry_cap_s=retry_cap_s,
            retry_statuses=retry_statuses,
        )
        latencies_ms.append(dt_ms)

        if resp is None:
            rows.append(
                {
                    "id": c.cid,
                    "category": c.category,
                    "expected": c.expected,
                    "predicted": "ALLOW",
                    "actions": [],
                    "risk_score": 0.0,
                    "message": f"REQUEST_ERROR: {req_err}",
                    "latency_ms": round(dt_ms, 3),
                    "correct": c.expected == "ALLOW",
                    "http_status": 0,
                    "attempts": attempts,
                }
            )
            continue

        if resp.status_code != 200:
            rows.append(
                {
                    "id": c.cid,
                    "category": c.category,
                    "expected": c.expected,
                    "predicted": "ALLOW",
                    "actions": [],
                    "risk_score": 0.0,
                    "message": f"HTTP {resp.status_code}",
                    "latency_ms": round(dt_ms, 3),
                    "correct": c.expected == "ALLOW",
                    "http_status": resp.status_code,
                    "attempts": attempts,
                }
            )
            continue

        data = resp.json()
        actions = data.get("actions") or []
        predicted = pred_label(actions)
        rows.append(
            {
                "id": c.cid,
                "category": c.category,
                "expected": c.expected,
                "predicted": predicted,
                "actions": actions,
                "risk_score": round(float(data.get("risk_score", 0.0) or 0.0), 4),
                "message": data.get("decision_message"),
                "latency_ms": round(dt_ms, 3),
                "correct": predicted == c.expected,
                "http_status": resp.status_code,
                "attempts": attempts,
            }
        )

    session_events = None
    try:
        sessions = requests.get(f"{api_base}/sessions", headers=headers, timeout=timeout)
        sessions.raise_for_status()
        for item in sessions.json().get("sessions", []):
            if item.get("id") == session_id:
                session_events = int(item.get("events", 0))
                break
    except requests.RequestException:
        session_events = None

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

    availability = round(sum(1 for r in rows if r["http_status"] == 200) / max(1, len(rows)), 4)
    retries_used = sum(max(0, int(r.get("attempts", 1)) - 1) for r in rows)
    http_429 = sum(1 for r in rows if r["http_status"] == 429)
    non_200 = sum(1 for r in rows if r["http_status"] != 200)

    out = {
        "benchmark_mode": "api_e2e",
        "api_base": api_base,
        "dataset": str(dataset),
        "n_cases": len(rows),
        "session_id": session_id,
        "session_events": session_events,
        "health": health_json,
        "metrics": metrics,
        "latency": latency,
        "reliability": {
            "availability_200": availability,
            "strict_accuracy_non200_fail": strict_accuracy(rows),
            "non_200_count": non_200,
            "http_429_count": http_429,
            "total_retries_used": retries_used,
            "max_retries": max_retries,
            "retry_base_s": retry_base_s,
            "retry_cap_s": retry_cap_s,
            "retry_statuses": sorted(retry_statuses),
        },
        "category_accuracy": {
            k: {"accuracy": round(v["correct"] / max(1, v["total"]), 4), "total": v["total"]}
            for k, v in sorted(by_category.items())
        },
        "errors": [r for r in rows if not r["correct"]],
        "rows": rows,
    }

    out_json.write_text(json.dumps(out, indent=2), encoding="utf-8")

    lines = [
        "Aegis API End-to-End Benchmark Summary",
        f"API: {api_base}",
        f"Dataset: {dataset}",
        f"Cases: {out['n_cases']}",
        f"Session ID: {session_id}",
        f"Session events (from /sessions): {session_events}",
        f"Health llm_enabled: {health_json.get('llm_enabled')}",
        f"Accuracy: {metrics['accuracy']}",
        f"Macro-F1: {metrics['macro_f1']}",
        f"Latency mean/p50/max (ms): {latency['mean_ms']} / {latency['p50_ms']} / {latency['max_ms']}",
        f"Availability (HTTP 200): {availability}",
        f"Strict accuracy (non-200 fail): {strict_accuracy(rows)}",
        f"Non-200 count: {non_200}",
        f"HTTP 429 count: {http_429}",
        f"Total retries used: {retries_used}",
        "Confusion Matrix (expected -> predicted):",
    ]
    for e in CLASSES:
        lines.append(f"  {e}: " + ", ".join(f"{p}:{metrics['confusion'][e][p]}" for p in CLASSES))
    out_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Wrote", out_json)
    print("Wrote", out_txt)
    print("Session:", session_id, "events:", session_events)
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=str(ROOT / "research" / "aegis_payloads_clean_1200.txt"))
    parser.add_argument("--out-prefix", default="benchmark_clean1200_api_e2e")
    parser.add_argument("--api-base", default="http://127.0.0.1:8000/v1")
    parser.add_argument("--api-key", default="changeme")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--retry-base-s", type=float, default=0.2)
    parser.add_argument("--retry-cap-s", type=float, default=2.0)
    parser.add_argument("--retry-statuses", default="429,500,502,503,504")
    args = parser.parse_args()

    retry_statuses = {
        int(x.strip())
        for x in str(args.retry_statuses).split(",")
        if x.strip()
    }
    run_benchmark(
        Path(args.dataset),
        args.out_prefix,
        args.api_base,
        args.api_key,
        args.timeout,
        max_retries=args.max_retries,
        retry_base_s=args.retry_base_s,
        retry_cap_s=args.retry_cap_s,
        retry_statuses=retry_statuses,
    )


if __name__ == "__main__":
    main()
