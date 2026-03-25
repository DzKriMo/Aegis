from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import re

from ..detectors.semantic import SemanticMatcher
from ..config import settings


@dataclass
class PolicyDecision:
    blocked: bool = False
    redact: bool = False
    warn: bool = False
    require_approval: bool = False
    modified_text: Optional[str] = None
    message: Optional[str] = None
    redaction: Optional[str] = None
    risk_score: float = 0.0
    matched_rules: List[str] | None = None

    def actions(self) -> List[str]:
        actions = []
        if self.blocked:
            actions.append("block")
        if self.redact:
            actions.append("redact")
        if self.warn:
            actions.append("warn")
        if self.require_approval:
            actions.append("require_approval")
        if self.modified_text is not None:
            actions.append("modify")
        return actions

    def apply_redaction(self, text: str) -> str:
        if self.redact and self.redaction:
            return self.redaction
        return text

    def to_dict(self) -> Dict[str, Any]:
        return {
            "blocked": self.blocked,
            "redact": self.redact,
            "warn": self.warn,
            "require_approval": self.require_approval,
            "modified_text": self.modified_text,
            "message": self.message,
            "redaction": self.redaction,
            "risk_score": self.risk_score,
            "matched_rules": list(self.matched_rules or []),
        }


class PolicyEngine:
    _KNOWN_STAGES = {"prellm", "postllm", "tool_pre", "tool_post"}

    def __init__(self, policies: List[Dict[str, Any]], fail_closed: Optional[bool] = None):
        self.policies = policies
        self.fail_closed = settings.aegis_fail_closed if fail_closed is None else fail_closed

    def evaluate(self, text: str, stage: str, detectors, context: Dict[str, Any]) -> PolicyDecision:
        if stage not in self._KNOWN_STAGES:
            if self.fail_closed:
                return PolicyDecision(
                    blocked=True,
                    message=f"Unknown policy stage '{stage}'",
                    risk_score=1.0,
                )
            return PolicyDecision()

        decision = PolicyDecision()
        decision.matched_rules = []
        try:
            for rule in self.policies:
                if rule.get("stage") and rule["stage"] != stage:
                    continue
                if self._matches(rule, text, detectors, context):
                    decision.matched_rules.append(str(rule.get("id") or "unnamed"))
                    decision.risk_score += float(rule.get("risk", 0.0))
                    action = rule.get("action")
                    if action == "block":
                        return PolicyDecision(blocked=True, message=rule.get("message"), risk_score=decision.risk_score, matched_rules=list(decision.matched_rules))
                    if action == "redact":
                        decision.redact = True
                        decision.redaction = rule.get("redaction", "[REDACTED]")
                    if action == "warn":
                        decision.warn = True
                        decision.message = rule.get("message")
                    if action == "approve":
                        decision.require_approval = True
                        decision.message = rule.get("message", "Approval required")
                    if action == "modify":
                        decision.modified_text = rule.get("replace_with")
        except Exception as exc:
            if self.fail_closed:
                return PolicyDecision(
                    blocked=True,
                    message=f"Policy evaluation error: {exc}",
                    risk_score=1.0,
                )
        return decision

    def _matches(self, rule: Dict[str, Any], text: str, detectors, context: Dict[str, Any]) -> bool:
        match = rule.get("match", {})
        any_matches = match.get("any", [])
        for m in any_matches:
            detector_name = m.get("detector")
            if detector_name and detectors.run(detector_name, text, context):
                return True
            semantic = m.get("semantic")
            if semantic:
                category = semantic.get("category")
                threshold = semantic.get("threshold")
                if category:
                    matcher = SemanticMatcher.from_env()
                    if matcher.match_with_threshold(category, text, threshold):
                        return True
            regex = m.get("regex")
            if regex and re.search(regex, text, re.IGNORECASE):
                return True
            label = m.get("label")
            if label and label in (context.get("labels") or []):
                return True
            role = m.get("role")
            if role and role == context.get("role"):
                return True
            environment = m.get("environment")
            if environment and environment == context.get("environment"):
                return True
            tenant_id = m.get("tenant_id")
            if tenant_id and tenant_id == context.get("tenant_id"):
                return True
        return False
