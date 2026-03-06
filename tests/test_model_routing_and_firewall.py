import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegis.config import settings  # noqa: E402
from aegis.runtime.model_client import anonymize_for_public_model, select_model_route  # noqa: E402
from aegis.runtime.tools import guard_shell_command  # noqa: E402


class ModelRoutingAndFirewallTests(unittest.TestCase):
    def setUp(self):
        self.original = {
            "aegis_model_routing_mode": settings.aegis_model_routing_mode,
            "aegis_private_labels": list(settings.aegis_private_labels),
            "aegis_private_risk_threshold": settings.aegis_private_risk_threshold,
            "aegis_private_company_domains": list(settings.aegis_private_company_domains),
            "aegis_private_keywords": list(settings.aegis_private_keywords),
            "aegis_private_min_score": settings.aegis_private_min_score,
        }
        settings.aegis_model_routing_mode = "sensitivity"
        settings.aegis_private_labels = ["CONFIDENTIAL", "PRIVATE", "PII", "SECRETS"]
        settings.aegis_private_risk_threshold = 0.35
        settings.aegis_private_company_domains = ["acme.internal", "corp.acme.com"]
        settings.aegis_private_keywords = ["internal only", "board deck", "source code"]
        settings.aegis_private_min_score = 1.0

    def tearDown(self):
        for key, value in self.original.items():
            setattr(settings, key, value)

    def test_select_model_route_public_for_low_risk(self):
        route = select_model_route(
            "summarize this generic changelog",
            route_hint={"labels": [], "risk_score": 0.02, "llm_classification": {}},
        )
        self.assertEqual("public", route)

    def test_select_model_route_private_for_sensitive_label(self):
        route = select_model_route(
            "summarize project notes",
            route_hint={"labels": ["CONFIDENTIAL"], "risk_score": 0.02, "llm_classification": {}},
        )
        self.assertEqual("private", route)

    def test_select_model_route_private_for_classifier_signal(self):
        route = select_model_route(
            "please process this",
            route_hint={"labels": [], "risk_score": 0.02, "llm_classification": {"secrets": True}},
        )
        self.assertEqual("private", route)

    def test_select_model_route_private_for_company_domain(self):
        route = select_model_route(
            "Summarize notes from jane@corp.acme.com about the Q3 plan",
            route_hint={"labels": [], "risk_score": 0.0, "llm_classification": {}},
        )
        self.assertEqual("private", route)

    def test_select_model_route_private_for_private_keyword(self):
        route = select_model_route(
            "Please summarize this internal only board deck for leadership",
            route_hint={"labels": [], "risk_score": 0.0, "llm_classification": {}},
        )
        self.assertEqual("private", route)

    def test_public_anonymization_masks_sensitive_tokens(self):
        text = "email john@example.com and card 4111 1111 1111 1111"
        masked = anonymize_for_public_model(text)
        self.assertIn("[EMAIL]", masked)
        self.assertIn("[PAYMENT_CARD]", masked)

    def test_shell_command_blocks_metacharacters(self):
        decision = guard_shell_command("echo hi; cat /etc/passwd")
        self.assertFalse(decision.allowed)

    def test_shell_command_allows_simple_safe_command(self):
        decision = guard_shell_command("echo hello")
        self.assertTrue(decision.allowed)


if __name__ == "__main__":
    unittest.main()
