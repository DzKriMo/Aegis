import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegis.runtime.runner import GuardedRuntime  # noqa: E402
from aegis.storage.store import InMemoryStore  # noqa: E402


class PostLLMIntegrationTests(unittest.TestCase):
    def setUp(self):
        os.environ.setdefault("AEGIS_LLM_ENABLED", "false")
        self.runtime = GuardedRuntime(store=InMemoryStore())
        self.session_id = "postllm-integration-session"
        self.runtime.store.create_session(self.session_id)

    def test_guard_model_output_emits_postllm_hooks(self):
        result = self.runtime.guard_model_output(
            session_id=self.session_id,
            output_text="This is definitely guaranteed and certainly correct.",
            metadata={},
        )
        self.assertIn("risk_score", result)

        session = self.runtime.store.get_session(self.session_id)
        stages = [event.get("stage") for event in session.get("events", [])]
        self.assertIn("output_firewall.grounding", stages)
        self.assertIn("output_firewall.risk", stages)
        self.assertIn("output_firewall.audit", stages)
        self.assertIn("postllm.response", stages)

    def test_least_privilege_blocks_shell_for_non_admin(self):
        result = self.runtime.guard_tool_call_pre(
            session_id=self.session_id,
            tool_name="shell",
            payload={"cmd": "ls"},
            environment="dev",
            role="employee",
        )
        self.assertTrue(result["blocked"])
        self.assertFalse(result["allowed"])
        self.assertIn("admin", (result.get("message") or "").lower())

    def test_least_privilege_blocks_http_fetch_write_methods(self):
        result = self.runtime.guard_tool_call_pre(
            session_id=self.session_id,
            tool_name="http_fetch",
            payload={"url": "https://example.com", "method": "POST"},
            environment="dev",
            role="admin",
        )
        self.assertTrue(result["blocked"])
        self.assertFalse(result["allowed"])
        self.assertIn("get/head", (result.get("message") or "").lower())


if __name__ == "__main__":
    unittest.main()
