from __future__ import annotations

from dataclasses import dataclass
from typing import List
import re


_HIGH_RISK_CONTENT_RE = re.compile(
	r"\b(rm\s+-rf|drop\s+table|exfiltrate|bypass\s+auth|steal\s+credentials)\b",
	re.IGNORECASE,
)


@dataclass
class PostLLMRiskResult:
	final_risk: float
	added_risk: float
	require_approval: bool
	reasons: List[str]


def score_postllm_risk(base_risk: float, model_output: str, grounding_risk: float, blocked: bool) -> PostLLMRiskResult:
	reasons: List[str] = []
	added = 0.0

	if grounding_risk > 0.0:
		added += min(grounding_risk, 0.35)
		reasons.append("grounding_uncertainty")

	if _HIGH_RISK_CONTENT_RE.search(str(model_output or "")):
		added += 0.25
		reasons.append("high_risk_content_pattern")

	final_risk = min(max(float(base_risk) + added, 0.0), 2.0)
	require_approval = (not blocked) and final_risk >= 0.9
	if require_approval:
		reasons.append("postllm_risk_threshold")

	return PostLLMRiskResult(
		final_risk=final_risk,
		added_risk=added,
		require_approval=require_approval,
		reasons=reasons,
	)
