import os
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegis.policies.loader import load_policies  # noqa: E402
from aegis.policies.engine import PolicyEngine  # noqa: E402
from aegis.detectors.registry import DetectorRegistry  # noqa: E402
from aegis.runtime.runner import GuardedRuntime  # noqa: E402
from aegis.storage.store import InMemoryStore  # noqa: E402


class GuardrailRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("AEGIS_LLM_ENABLED", "false")
        cls.detectors = DetectorRegistry.default()
        cls.engine = PolicyEngine(load_policies(), fail_closed=True)
        cls.runtime = GuardedRuntime(store=InMemoryStore())
        cls.session_id = "regression-session"
        cls.runtime.store.create_session(cls.session_id)
        corpus_path = ROOT / "tests" / "data" / "guardrail_regression_cases.yaml"
        with open(corpus_path, "r", encoding="utf-8") as f:
            cls.cases = (yaml.safe_load(f) or {}).get("cases", [])

    def test_attack_corpus(self):
        for case in self.cases:
            with self.subTest(case=case["id"]):
                kind = case["kind"]
                if kind == "message":
                    result = self.runtime.handle_user_message(
                        session_id=self.session_id,
                        content=case["content"],
                        metadata={},
                    )
                    for action in case.get("expected_actions", []):
                        self.assertIn(action, result.actions)
                    for action in case.get("expected_not_actions", []):
                        self.assertNotIn(action, result.actions)
                    if "expected_risk_min" in case:
                        self.assertGreaterEqual(result.risk_score, float(case["expected_risk_min"]))

                    session = self.runtime.store.get_session(self.session_id)
                    self.assertTrue(session.get("events"))
                    self.assertIn("ts_readable", session["events"][-1])
                elif kind == "policy_eval":
                    decision = self.engine.evaluate(
                        text=case["content"],
                        stage=case["stage"],
                        detectors=self.detectors,
                        context={"labels": [], "metadata": {}},
                    )
                    expected = case.get("expected", {})
                    if "blocked" in expected:
                        self.assertEqual(expected["blocked"], decision.blocked)
                    if "redact" in expected:
                        self.assertEqual(expected["redact"], decision.redact)
                elif kind == "tool":
                    tool_result = self.runtime.handle_tool_call(
                        session_id=self.session_id,
                        tool_name=case["tool_name"],
                        payload=case.get("payload", {}),
                        environment=case.get("environment"),
                        allowlist=[],
                        denylist=[],
                        filesystem_root=None,
                    )
                    expected = case.get("expected", {})
                    if "allowed" in expected:
                        self.assertEqual(expected["allowed"], tool_result["allowed"])
                    if expected.get("has_approval_hash"):
                        self.assertTrue(bool(tool_result.get("approval_hash")))
                    if "message_contains" in expected:
                        msg = (tool_result.get("message") or "").lower()
                        self.assertIn(expected["message_contains"].lower(), msg)
                else:
                    self.fail(f"Unsupported case kind: {kind}")

    def test_trusted_local_summary_secret_match_becomes_approval_not_block(self):
        runtime = GuardedRuntime(store=InMemoryStore())
        session_id = "trusted-local-summary"
        runtime.store.create_session(session_id)

        result = runtime.guard_model_output(
            session_id=session_id,
            output_text="The README explains how to configure the app with an API key stored in .env.",
            metadata={
                "source": "real_guarded_agent",
                "derived_from_tool": "filesystem_read",
                "tool_trust": "high",
                "summary_mode": True,
            },
            environment="dev",
        )

        self.assertFalse(result["blocked"])
        self.assertTrue(result["require_approval"])
        self.assertIn("approval", (result.get("message") or "").lower())

    def test_benign_local_file_summary_is_not_secret_or_exfiltration(self):
        detectors = DetectorRegistry.default()
        context = {
            "labels": [],
            "environment": "dev",
            "metadata": {
                "source": "real_guarded_agent",
                "derived_from_tool": "filesystem_read",
                "tool_trust": "high",
                "summary_mode": True,
            },
            "risk_state": {},
        }
        text = "The file krimo.txt contains: 'KriMo elm9wd fl Informatique'."

        self.assertFalse(detectors.run("secrets", text, dict(context)))
        self.assertFalse(detectors.run("exfiltration", text, dict(context)))

        decision = self.engine.evaluate(text=text, stage="postllm", detectors=detectors, context=dict(context))
        self.assertFalse(decision.blocked)


if __name__ == "__main__":
    unittest.main()
