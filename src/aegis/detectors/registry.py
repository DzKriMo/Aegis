from typing import Callable, Dict
from .simple import (
    detect_prompt_injection,
    detect_pii,
    detect_secrets,
    detect_policy_violation,
    detect_exfiltration,
    detect_goal_hijack,
    detect_jailbreak,
    detect_data_leakage,
    detect_high_risk_abuse,
    detect_suspicious_disclosure,
    detect_caution_disclosure,
    detect_ml_block_intent,
    detect_ml_warn_intent,
)
from .llm_client import classify_text


class DetectorRegistry:
    def __init__(self, detectors: Dict[str, Callable[[str, Dict], bool]]):
        self.detectors = detectors

    @classmethod
    def default(cls):
        return cls(
            {
                "prompt_injection": detect_prompt_injection,
                "jailbreak": detect_jailbreak,
                "pii": detect_pii,
                "secrets": detect_secrets,
                "policy_violation": detect_policy_violation,
                "exfiltration": detect_exfiltration,
                "data_leakage": detect_data_leakage,
                "goal_hijack": detect_goal_hijack,
                "high_risk_abuse": detect_high_risk_abuse,
                "suspicious_disclosure": detect_suspicious_disclosure,
                "caution_disclosure": detect_caution_disclosure,
                "ml_block_intent": detect_ml_block_intent,
                "ml_warn_intent": detect_ml_warn_intent,
            }
        )

    def run(self, name: str, text: str, context: Dict) -> bool:
        fn = self.detectors.get(name)
        if not fn:
            return False
        if "llm_classification" not in context:
            context["llm_classification"] = classify_text(text)
        return fn(text, context)
