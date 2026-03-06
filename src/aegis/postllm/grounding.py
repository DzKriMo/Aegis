from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List
import re


_ASSERTIVE_CLAIMS_RE = re.compile(
	r"\b(always|never|guaranteed|definitely|proven|certainly|100\s*%)\b",
	re.IGNORECASE,
)


@dataclass
class GroundingAssessment:
	grounded: bool
	risk_score: float
	reasons: List[str]


def assess_grounding(output_text: str, context: Dict[str, Any] | None = None) -> GroundingAssessment:
	context = context or {}
	metadata = context.get("metadata") or {}
	evidence = metadata.get("evidence") or metadata.get("sources") or []

	text = str(output_text or "").strip()
	reasons: List[str] = []
	score = 0.0

	if not text:
		reasons.append("empty_output")
		score += 0.15

	if _ASSERTIVE_CLAIMS_RE.search(text):
		reasons.append("assertive_claim_language")
		score += 0.2

	if not evidence and len(text) > 500:
		reasons.append("no_evidence_context")
		score += 0.2

	grounded = score < 0.35
	return GroundingAssessment(grounded=grounded, risk_score=min(max(score, 0.0), 1.0), reasons=reasons)
