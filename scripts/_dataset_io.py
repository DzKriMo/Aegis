import csv
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List

ROW_RE = re.compile(r"^\[(allow|warn|block)\]\s*\(([^)]+)\)\s*(.+)$", re.IGNORECASE)


def _norm_label(raw: str) -> str:
    v = (raw or "").strip().upper()
    if v in {"ALLOW", "WARN", "BLOCK"}:
        return v
    low = v.lower()
    if any(k in low for k in ("allow", "benign", "safe", "normal", "clean")):
        return "ALLOW"
    if any(k in low for k in ("warn", "suspicious", "gray", "grey", "uncertain", "caution")):
        return "WARN"
    if any(k in low for k in ("block", "malicious", "attack", "jailbreak", "inject")):
        return "BLOCK"
    return ""


def _pick_text(rec: Dict) -> str:
    keys = [
        "text",
        "prompt",
        "input",
        "content",
        "query",
        "instruction",
        "request",
        "message",
    ]
    for k in keys:
        v = rec.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _pick_label(rec: Dict) -> str:
    keys = ["label", "class", "target", "risk", "category_label", "expected"]
    for k in keys:
        v = rec.get(k)
        if isinstance(v, (str, int, float)):
            lab = _norm_label(str(v))
            if lab:
                return lab
    return ""


def _pick_category(rec: Dict) -> str:
    keys = ["category", "type", "attack_type", "group", "tag"]
    for k in keys:
        v = rec.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "unknown"


def parse_bracket_file(path: Path, source: str) -> List[Dict]:
    rows = []
    idx = 0
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        m = ROW_RE.match(s)
        if not m:
            continue
        idx += 1
        label, category, text = m.groups()
        rows.append(
            {
                "id": f"{source}_{idx:06d}",
                "label": label.upper(),
                "category": category.strip(),
                "text": text.strip(),
                "source": source,
            }
        )
    return rows


def parse_jsonl_file(path: Path, source: str) -> List[Dict]:
    rows = []
    idx = 0
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = raw.strip()
        if not s:
            continue
        try:
            rec = json.loads(s)
        except Exception:
            continue
        text = _pick_text(rec)
        label = _pick_label(rec)
        if not text or not label:
            continue
        idx += 1
        rows.append(
            {
                "id": f"{source}_{idx:06d}",
                "label": label,
                "category": _pick_category(rec),
                "text": text,
                "source": source,
            }
        )
    return rows


def parse_csv_file(path: Path, source: str) -> List[Dict]:
    rows = []
    idx = 0
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        for rec in reader:
            text = _pick_text(rec)
            label = _pick_label(rec)
            if not text or not label:
                continue
            idx += 1
            rows.append(
                {
                    "id": f"{source}_{idx:06d}",
                    "label": label,
                    "category": _pick_category(rec),
                    "text": text,
                    "source": source,
                }
            )
    return rows


def load_any(path: Path, source: str) -> List[Dict]:
    suf = path.suffix.lower()
    if suf == ".jsonl":
        return parse_jsonl_file(path, source)
    if suf == ".csv":
        return parse_csv_file(path, source)
    return parse_bracket_file(path, source)


def write_jsonl(path: Path, rows: Iterable[Dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=True) + "\n")


def normalize_text_key(s: str) -> str:
    return " ".join((s or "").lower().split())

