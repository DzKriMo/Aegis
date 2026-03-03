import argparse
import json
from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegis.policies.validate import validate_policies_schema


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--path", default="config/policies.example.yaml")
    args = p.parse_args()

    path = Path(args.path)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    policies = data.get("policies", [])
    validate_policies_schema(policies)
    print(json.dumps({"ok": True, "path": str(path), "count": len(policies)}, indent=2))


if __name__ == "__main__":
    main()
