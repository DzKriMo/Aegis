import sys
import unittest
from pathlib import Path
import uuid

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegis.config import settings  # noqa: E402
from aegis.policies.loader import load_policies  # noqa: E402


class PolicyValidationTests(unittest.TestCase):
    def setUp(self):
        self.original = {
            "policy_path": settings.policy_path,
            "aegis_strict_policy_load": settings.aegis_strict_policy_load,
            "aegis_db_enabled": settings.aegis_db_enabled,
        }
        settings.aegis_db_enabled = False
        settings.aegis_strict_policy_load = True

    def tearDown(self):
        for key, value in self.original.items():
            setattr(settings, key, value)

    def test_valid_policy_file_loads(self):
        settings.policy_path = "config/policies.example.yaml"
        policies = load_policies()
        self.assertGreater(len(policies), 0)

    def test_invalid_yaml_fails_in_strict_mode(self):
        p = ROOT / "research" / f"bad_policy_{uuid.uuid4().hex}.yaml"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("policies:\n  - id: x\n    stage: prellm\n    action: warn\n    message: bad: yaml\n", encoding="utf-8")
        try:
            settings.policy_path = str(p)
            with self.assertRaises(RuntimeError):
                load_policies()
        finally:
            if p.exists():
                p.unlink()

    def test_schema_violation_fails_in_strict_mode(self):
        p = ROOT / "research" / f"bad_schema_policy_{uuid.uuid4().hex}.yaml"
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {"policies": [{"id": "x", "stage": "invalid", "action": "warn", "match": {"any": [{"detector": "x"}]}}]}
        p.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
        try:
            settings.policy_path = str(p)
            with self.assertRaises(RuntimeError):
                load_policies()
        finally:
            if p.exists():
                p.unlink()


if __name__ == "__main__":
    unittest.main()
