from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import json
import re
from uuid import uuid4

from ..policies.engine import PolicyEngine
from ..policies.loader import load_policies
from ..detectors.registry import DetectorRegistry
from ..detectors.llm_client import classify_text
from ..detectors.local_classifier import classify_guardrail_label
from ..prellm.normalize import normalize_text
from ..prellm.network import evaluate_urls
from ..postllm.approval import approval_hash
from ..postllm import (
    assess_grounding,
    build_audit_evidence,
    enforce_least_privilege,
    score_postllm_risk,
)
from ..config import settings
from .model_client import generate_text
from .risk_control import (
    dynamic_thresholds,
    is_sensitive_tool,
    should_quarantine,
    tool_risk_modifier,
    update_trajectory_risk,
)
from .tool_router import execute_tool


@dataclass
class RuntimeResult:
    output: str
    actions: List[str]
    risk_score: float
    message: Optional[str]
    approval_hash: Optional[str]
    metadata: Dict[str, Any]


class GuardedRuntime:
    OUTPUT_FIREWALL_STAGE = "output_firewall"
    OUTPUT_FIREWALL_GROUNDING_STAGE = "output_firewall.grounding"
    OUTPUT_FIREWALL_RISK_STAGE = "output_firewall.risk"
    OUTPUT_FIREWALL_AUDIT_STAGE = "output_firewall.audit"
    OUTPUT_FIREWALL_TRANSFORM_STAGE = "output_firewall.transform"
    POSTLLM_RESPONSE_STAGE = "postllm.response"

    def __init__(self, store):
        self.store = store
        self.detectors = DetectorRegistry.default()
        self.policy_engine = PolicyEngine(load_policies())
        self._tool_injection_re = re.compile(
            r"(ignore\s+previous|system\s+prompt|developer\s+mode|disable\s+guardrails|<script|[A-Za-z0-9+/]{28,}={0,2})",
            re.IGNORECASE,
        )

    def _default_risk_state(self) -> Dict[str, Any]:
        return {
            "cumulative_risk_score": 0.0,
            "goal_drift_score": 0.0,
            "injection_attempt_count": 0,
            "sensitive_tool_attempts": 0,
            "quarantined": False,
            "last_event_hash": "GENESIS",
        }

    def _get_risk_state(self, session_id: str) -> Dict[str, Any]:
        getter = getattr(self.store, "get_risk_state", None)
        if callable(getter):
            got = getter(session_id) or {}
            if got:
                return got
        return self._default_risk_state()

    def _set_risk_state(self, session_id: str, state: Dict[str, Any]) -> None:
        setter = getattr(self.store, "set_risk_state", None)
        if callable(setter):
            setter(session_id, state)

    def _scan_tool_output_for_injection(self, result: Dict[str, Any]) -> bool:
        return bool(self._tool_injection_re.search(json.dumps(result or {}, ensure_ascii=True)))

    def _apply_text_decision(self, text: str, decision) -> str:
        transformed = decision.apply_redaction(text)
        if decision.modified_text is not None:
            transformed = decision.modified_text
        return transformed

    def _mask_strings(self, value: Any, replacement: str) -> Any:
        if isinstance(value, str):
            return replacement
        if isinstance(value, list):
            return [self._mask_strings(v, replacement) for v in value]
        if isinstance(value, dict):
            return {k: self._mask_strings(v, replacement) for k, v in value.items()}
        return value

    def _build_model_output(self, prompt_text: str, route_hint: Optional[Dict[str, Any]] = None) -> tuple[str, Dict[str, Any]]:
        cleaned = " ".join((prompt_text or "").strip().split())
        if not cleaned:
            cleaned = "[empty input]"
        cleaned = cleaned[:1200]
        if settings.aegis_model_enabled:
            generated, meta = generate_text(cleaned, route_hint=route_hint, return_meta=True)
            return generated, meta
        return f"Model draft: {cleaned}", {"route": "disabled", "model": "disabled", "endpoint": "", "anonymized": False}

    def _decision_severity(self, decision) -> int:
        if getattr(decision, "blocked", False):
            return 3
        if getattr(decision, "require_approval", False):
            return 2
        if getattr(decision, "warn", False):
            return 1
        return 0

    def _policy_block_message(self, reason: Optional[str] = None, user_request: Optional[str] = None) -> str:
        request_text = " ".join(str(user_request or "").split())[:600]
        reason_text = " ".join(str(reason or "").split())[:280]
        if settings.aegis_model_enabled and request_text:
            try:
                prompt = (
                    "You are a safety assistant. The user's request cannot be answered directly due to policy. "
                    "Write a concise refusal plus 2 safe alternatives tailored to the request context. "
                    "Do not include harmful instructions, operational abuse steps, or evasion tips. "
                    "Keep it under 90 words.\n"
                    f"User request: {request_text}\n"
                    f"Policy reason: {reason_text or 'policy restriction'}"
                )
                generated = str(generate_text(prompt, route_hint={"policy_risk_score": 1.0}) or "").strip()
                if generated:
                    return generated
            except Exception:
                pass

        base = (
            "I can't answer that request because it goes against policy. "
            "I can help with a safer alternative, like high-level guidance, defensive best practices, "
            "or a compliant version of your question."
        )
        if reason_text:
            return f"{base} Reason: {reason_text}"
        return base

    def _policy_warning_message(self, reason: Optional[str] = None, user_request: Optional[str] = None) -> str:
        request_text = " ".join(str(user_request or "").split())[:600]
        reason_text = " ".join(str(reason or "").split())[:280]
        if settings.aegis_model_enabled and request_text:
            try:
                prompt = (
                    "You are a safety assistant. The request is partially risky and needs a constrained response. "
                    "Write a short warning sentence and suggest 1-2 safe alternatives specific to the request context. "
                    "Do not include harmful instructions. Keep it under 70 words.\n"
                    f"User request: {request_text}\n"
                    f"Policy reason: {reason_text or 'possible policy risk'}"
                )
                generated = str(generate_text(prompt, route_hint={"policy_risk_score": 0.8}) or "").strip()
                if generated:
                    return generated
            except Exception:
                pass

        base = (
            "Policy warning: this request may violate policy, so the response is limited. "
            "If you want, rephrase toward safe intent and I can provide a compliant alternative."
        )
        if reason_text:
            return f"{base} Reason: {reason_text}"
        return base

    def guard_user_input(
        self,
        session_id: str,
        content: str,
        metadata: Dict[str, Any],
        tenant_id: Optional[str] = None,
        role: Optional[str] = None,
        environment: Optional[str] = None,
        labels: Optional[List[str]] = None,
        url_allowlist: Optional[List[str]] = None,
        url_denylist: Optional[List[str]] = None,
        urls: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        request_id = str(uuid4())
        labels = labels or []
        url_allowlist = url_allowlist or []
        url_denylist = url_denylist or []
        urls = urls or []
        risk_state = self._get_risk_state(session_id)
        context = {
            "tenant_id": tenant_id,
            "role": role,
            "environment": environment,
            "labels": labels,
            "metadata": metadata,
            "risk_state": risk_state,
        }

        def _log(event: Dict[str, Any]) -> None:
            payload = dict(event)
            payload["request_id"] = request_id
            payload["flow"] = "message"
            self.store.log_event(session_id, payload)

        normalized, norm_flags = normalize_text(content)
        if norm_flags:
            _log(
                {
                    "stage": "prellm.normalize",
                    "content": content,
                    "normalized": normalized,
                    "flags": norm_flags,
                },
            )

        try:
            llm_cls = classify_text(normalized)
        except Exception as exc:
            if settings.aegis_fail_closed:
                return {
                    "allowed": False,
                    "blocked": True,
                    "require_approval": False,
                    "message": f"LLM classification error: {exc}",
                    "risk_score": 1.0,
                    "approval_hash": None,
                    "sanitized_content": None,
                }
            llm_cls = {"__error__": str(exc)}

        context["llm_classification"] = llm_cls
        _log(
            {
                "stage": "llm_classification",
                "scope": "input",
                "content": normalized,
                "classification": llm_cls,
            },
        )

        local_cls = classify_guardrail_label(normalized)
        context["local_classification"] = local_cls
        dyn = dynamic_thresholds(local_cls, risk_state, settings.aegis_guardrail_profile)
        context["local_block_threshold"] = dyn.block
        context["local_warn_threshold"] = dyn.warn
        context["ood_score"] = dyn.ood_score
        _log(
            {
                "stage": "local_classification",
                "scope": "input",
                "content": normalized,
                "classification": local_cls,
                "dynamic_thresholds": {
                    "block": dyn.block,
                    "warn": dyn.warn,
                    "ood_score": dyn.ood_score,
                    "ood_entropy": dyn.ood_entropy,
                    "ood_distance": dyn.ood_distance,
                    "penalty": dyn.penalty,
                },
            },
        )

        if urls:
            net_decision = evaluate_urls(urls, allowlist=url_allowlist, denylist=url_denylist)
            _log(
                {
                    "stage": "prellm.network",
                    "urls": urls,
                    "decision": net_decision.to_dict(),
                },
            )
            if net_decision.blocked:
                self._update_and_persist_risk_state(
                    session_id,
                    risk_state,
                    net_decision.risk_score,
                    injection_signal=False,
                    tool_misuse_signal=False,
                    goal_drift_signal=True,
                )
                return {
                    "allowed": False,
                    "blocked": True,
                    "require_approval": False,
                    "message": net_decision.message or "Blocked",
                    "risk_score": net_decision.risk_score,
                    "approval_hash": None,
                    "sanitized_content": None,
                }

        decision = self.policy_engine.evaluate(normalized, stage="prellm", detectors=self.detectors, context=context)
        if not decision.blocked and not decision.warn and dyn.ood_score >= float(settings.aegis_ood_warn_threshold):
            decision.warn = True
            decision.message = "OOD uncertainty elevated; caution mode applied"
            decision.risk_score += 0.25
        _log(
            {
                "stage": "prellm",
                "content": normalized,
                "decision": decision.to_dict(),
            },
        )

        if decision.blocked:
            self._update_and_persist_risk_state(
                session_id,
                risk_state,
                decision.risk_score,
                injection_signal=True,
                tool_misuse_signal=False,
                goal_drift_signal=True,
            )
            return {
                "allowed": False,
                "blocked": True,
                "require_approval": False,
                "message": decision.message or "Blocked",
                "risk_score": decision.risk_score,
                "approval_hash": None,
                "sanitized_content": None,
            }

        if decision.require_approval:
            h = approval_hash(stage="prellm", content=normalized, context=context)
            if not self.store.is_approved(session_id, h):
                self.store.add_pending_approval(session_id, h)
                self._update_and_persist_risk_state(
                    session_id,
                    risk_state,
                    decision.risk_score,
                    injection_signal=False,
                    tool_misuse_signal=False,
                    goal_drift_signal=False,
                )
                return {
                    "allowed": False,
                    "blocked": False,
                    "require_approval": True,
                    "message": decision.message or "Approval required",
                    "risk_score": decision.risk_score,
                    "approval_hash": h,
                    "sanitized_content": None,
                }

        transformed_input = self._apply_text_decision(normalized, decision)
        if transformed_input != normalized:
            _log(
                {
                    "stage": "prellm.transform",
                    "input_original": normalized,
                    "input_transformed": transformed_input,
                },
            )
        return {
            "allowed": True,
            "blocked": False,
            "require_approval": False,
            "message": decision.message,
            "risk_score": decision.risk_score,
            "approval_hash": None,
            "sanitized_content": transformed_input,
        }

    def guard_model_output(
        self,
        session_id: str,
        output_text: str,
        metadata: Optional[Dict[str, Any]] = None,
        tenant_id: Optional[str] = None,
        role: Optional[str] = None,
        environment: Optional[str] = None,
        labels: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        request_id = str(uuid4())
        labels = labels or []
        metadata = metadata or {}
        risk_state = self._get_risk_state(session_id)
        context = {
            "tenant_id": tenant_id,
            "role": role,
            "environment": environment,
            "labels": labels,
            "metadata": metadata,
            "risk_state": risk_state,
        }

        def _log(event: Dict[str, Any]) -> None:
            payload = dict(event)
            payload["request_id"] = request_id
            payload["flow"] = "message"
            self.store.log_event(session_id, payload)

        out_decision = self.policy_engine.evaluate(output_text, stage="postllm", detectors=self.detectors, context=context)
        _log(
            {
                "stage": self.OUTPUT_FIREWALL_STAGE,
                "content": output_text,
                "decision": out_decision.to_dict(),
            },
        )

        grounding = assess_grounding(output_text, context=context)
        _log(
            {
                "stage": self.OUTPUT_FIREWALL_GROUNDING_STAGE,
                "grounded": grounding.grounded,
                "risk_score": grounding.risk_score,
                "reasons": grounding.reasons,
            },
        )
        risk_eval = score_postllm_risk(
            base_risk=out_decision.risk_score,
            model_output=output_text,
            grounding_risk=grounding.risk_score,
            blocked=out_decision.blocked,
        )
        final_risk = risk_eval.final_risk
        _log(
            {
                "stage": self.OUTPUT_FIREWALL_RISK_STAGE,
                "base_risk": out_decision.risk_score,
                "added_risk": risk_eval.added_risk,
                "final_risk": final_risk,
                "reasons": risk_eval.reasons,
            },
        )
        if risk_eval.require_approval and not out_decision.blocked:
            out_decision.require_approval = True
            if not out_decision.message:
                out_decision.message = "Post-LLM risk threshold exceeded: approval required"

        audit_evidence = build_audit_evidence(
            session_id=session_id,
            request_id=request_id,
            stage=self.OUTPUT_FIREWALL_STAGE,
            risk_score=final_risk,
            reasons=list(dict.fromkeys(grounding.reasons + risk_eval.reasons)),
            details={"decision": out_decision.to_dict()},
        )
        _log({"stage": self.OUTPUT_FIREWALL_AUDIT_STAGE, "evidence": audit_evidence})

        if out_decision.blocked:
            self._update_and_persist_risk_state(
                session_id,
                risk_state,
                final_risk,
                injection_signal=False,
                tool_misuse_signal=False,
                goal_drift_signal=True,
            )
            return {
                "allowed": False,
                "blocked": True,
                "require_approval": False,
                "message": out_decision.message or "Blocked",
                "risk_score": final_risk,
                "approval_hash": None,
                "sanitized_output": None,
            }

        if out_decision.require_approval:
            h = approval_hash(stage=self.OUTPUT_FIREWALL_STAGE, content=output_text, context=context)
            if not self.store.is_approved(session_id, h):
                self.store.add_pending_approval(session_id, h)
                self._update_and_persist_risk_state(
                    session_id,
                    risk_state,
                    final_risk,
                    injection_signal=False,
                    tool_misuse_signal=False,
                    goal_drift_signal=False,
                )
                return {
                    "allowed": False,
                    "blocked": False,
                    "require_approval": True,
                    "message": out_decision.message or "Approval required",
                    "risk_score": final_risk,
                    "approval_hash": h,
                    "sanitized_output": None,
                }

        sanitized = self._apply_text_decision(output_text, out_decision)
        if sanitized != output_text:
            _log(
                {
                    "stage": self.OUTPUT_FIREWALL_TRANSFORM_STAGE,
                    "output_original": output_text,
                    "output_transformed": sanitized,
                },
            )
        _log(
            {
                "stage": self.POSTLLM_RESPONSE_STAGE,
                "output": sanitized,
                "kind": "allow",
                "reason": out_decision.message,
            },
        )
        updated = self._update_and_persist_risk_state(
            session_id,
            risk_state,
            final_risk,
            injection_signal=False,
            tool_misuse_signal=False,
            goal_drift_signal=False,
        )
        _log({"stage": "risk.update", "final_risk": final_risk, "risk_state": updated})
        return {
            "allowed": True,
            "blocked": False,
            "require_approval": False,
            "message": out_decision.message,
            "risk_score": final_risk,
            "approval_hash": None,
            "sanitized_output": sanitized,
        }

    def _update_and_persist_risk_state(
        self,
        session_id: str,
        risk_state: Dict[str, Any],
        base_classifier_score: float,
        injection_signal: bool,
        tool_misuse_signal: bool,
        goal_drift_signal: bool,
    ) -> Dict[str, Any]:
        updated = update_trajectory_risk(
            risk_state,
            base_classifier_score=base_classifier_score,
            injection_signal=injection_signal,
            tool_misuse_signal=tool_misuse_signal,
            goal_drift_signal=goal_drift_signal,
        )
        updated["quarantined"] = bool(updated.get("quarantined", False)) or should_quarantine(updated)
        self._set_risk_state(session_id, updated)
        persisted = self._get_risk_state(session_id)
        updated["last_event_hash"] = persisted.get("last_event_hash", updated.get("last_event_hash", "GENESIS"))
        if updated.get("quarantined", False) and not risk_state.get("quarantined", False):
            self.store.log_event(
                session_id,
                {"stage": "risk.quarantine", "message": "Session entered quarantine mode", "risk_state": updated},
            )
        return updated

    def handle_user_message(
        self,
        session_id: str,
        content: str,
        metadata: Dict[str, Any],
        tenant_id: Optional[str] = None,
        role: Optional[str] = None,
        environment: Optional[str] = None,
        labels: Optional[List[str]] = None,
        url_allowlist: Optional[List[str]] = None,
        url_denylist: Optional[List[str]] = None,
        urls: Optional[List[str]] = None,
    ) -> RuntimeResult:
        request_id = str(uuid4())
        labels = labels or []
        url_allowlist = url_allowlist or []
        url_denylist = url_denylist or []
        urls = urls or []
        risk_state = self._get_risk_state(session_id)

        context = {
            "tenant_id": tenant_id,
            "role": role,
            "environment": environment,
            "labels": labels,
            "metadata": metadata,
            "risk_state": risk_state,
        }

        def _log(event: Dict[str, Any]) -> None:
            payload = dict(event)
            payload["request_id"] = request_id
            payload["flow"] = "message"
            self.store.log_event(session_id, payload)

        # 0) normalize input
        normalized, norm_flags = normalize_text(content)
        if norm_flags:
            _log(
                {
                    "stage": "prellm.normalize",
                    "content": content,
                    "normalized": normalized,
                    "flags": norm_flags,
                },
            )

        # 1) LLM classification (always log for visibility)
        try:
            llm_cls = classify_text(normalized)
        except Exception as exc:
            if settings.aegis_fail_closed:
                return RuntimeResult(
                    output="Blocked",
                    actions=["block"],
                    risk_score=1.0,
                    message=f"LLM classification error: {exc}",
                    approval_hash=None,
                    metadata={},
                )
            llm_cls = {"__error__": str(exc)}

        context["llm_classification"] = llm_cls
        _log(
            {
                "stage": "llm_classification",
                "scope": "input",
                "content": normalized,
                "classification": llm_cls,
            },
        )

        # 1b) local supervised classifier (optional, low latency)
        local_cls = classify_guardrail_label(normalized)
        context["local_classification"] = local_cls
        dyn = dynamic_thresholds(local_cls, risk_state, settings.aegis_guardrail_profile)
        context["local_block_threshold"] = dyn.block
        context["local_warn_threshold"] = dyn.warn
        context["ood_score"] = dyn.ood_score
        _log(
            {
                "stage": "local_classification",
                "scope": "input",
                "content": normalized,
                "classification": local_cls,
                "dynamic_thresholds": {
                    "block": dyn.block,
                    "warn": dyn.warn,
                    "ood_score": dyn.ood_score,
                    "ood_entropy": dyn.ood_entropy,
                    "ood_distance": dyn.ood_distance,
                    "penalty": dyn.penalty,
                },
            },
        )

        # 2) pre-LLM network firewall (if URLs provided)
        if urls:
            net_decision = evaluate_urls(urls, allowlist=url_allowlist, denylist=url_denylist)
            _log(
                {
                    "stage": "prellm.network",
                    "urls": urls,
                    "decision": net_decision.to_dict(),
                },
            )
            if net_decision.blocked:
                self._update_and_persist_risk_state(
                    session_id,
                    risk_state,
                    net_decision.risk_score,
                    injection_signal=False,
                    tool_misuse_signal=False,
                    goal_drift_signal=True,
                )
                refusal = self._policy_block_message(net_decision.message, normalized)
                _log({"stage": self.POSTLLM_RESPONSE_STAGE, "output": refusal, "kind": "block", "reason": net_decision.message})
                return RuntimeResult(
                    output=refusal,
                    actions=["block"],
                    risk_score=net_decision.risk_score,
                    message=net_decision.message,
                    approval_hash=None,
                    metadata={},
                )

        # 3) policy evaluate input
        decision = self.policy_engine.evaluate(normalized, stage="prellm", detectors=self.detectors, context=context)
        if not decision.blocked and not decision.warn and dyn.ood_score >= float(settings.aegis_ood_warn_threshold):
            decision.warn = True
            decision.message = "OOD uncertainty elevated; caution mode applied"
            decision.risk_score += 0.25
        _log(
            {
                "stage": "prellm",
                "content": normalized,
                "decision": decision.to_dict(),
            },
        )
        if decision.blocked:
            self._update_and_persist_risk_state(
                session_id,
                risk_state,
                decision.risk_score,
                injection_signal=True,
                tool_misuse_signal=False,
                goal_drift_signal=True,
            )
            refusal = self._policy_block_message(decision.message, normalized)
            _log({"stage": self.POSTLLM_RESPONSE_STAGE, "output": refusal, "kind": "block", "reason": decision.message})
            return RuntimeResult(
                output=refusal,
                actions=["block"],
                risk_score=decision.risk_score,
                message=decision.message,
                approval_hash=None,
                metadata={},
            )
        if decision.require_approval:
            h = approval_hash(stage="prellm", content=normalized, context=context)
            if not self.store.is_approved(session_id, h):
                self.store.add_pending_approval(session_id, h)
                self._update_and_persist_risk_state(
                    session_id,
                    risk_state,
                    decision.risk_score,
                    injection_signal=False,
                    tool_misuse_signal=False,
                    goal_drift_signal=False,
                )
                refusal = self._policy_block_message(decision.message or "Approval required", normalized)
                _log({"stage": self.POSTLLM_RESPONSE_STAGE, "output": refusal, "kind": "approval", "reason": decision.message})
                return RuntimeResult(
                    output=refusal,
                    actions=["require_approval"],
                    risk_score=decision.risk_score,
                    message=decision.message,
                    approval_hash=h,
                    metadata={},
                )

        pre_actions = [a for a in decision.actions() if a not in {"block", "require_approval"}]
        pre_risk = decision.risk_score
        pre_message = decision.message

        transformed_input = self._apply_text_decision(normalized, decision)
        if transformed_input != normalized:
            _log(
                {
                    "stage": "prellm.transform",
                    "input_original": normalized,
                    "input_transformed": transformed_input,
                },
            )

        # 4) model response
        try:
            model_hint = dict(context)
            model_hint["policy_risk_score"] = pre_risk
            model_output, model_meta = self._build_model_output(transformed_input, route_hint=model_hint)
            _log({"stage": "model", "input": transformed_input, "output": model_output, "model_route": model_meta})
        except Exception as exc:
            _log({"stage": "model.error", "input": transformed_input, "error": str(exc)})
            if settings.aegis_fail_closed:
                self._update_and_persist_risk_state(
                    session_id,
                    risk_state,
                    1.0,
                    injection_signal=False,
                    tool_misuse_signal=False,
                    goal_drift_signal=True,
                )
                return RuntimeResult(
                    output="Blocked",
                    actions=["block"],
                    risk_score=1.0,
                    message=f"Model generation error: {exc}",
                    approval_hash=None,
                    metadata={},
                )
            model_output = f"Model draft (fallback): {transformed_input[:500]}"
            _log({"stage": "model.fallback", "input": transformed_input, "output": model_output})

        # 5) post-LLM policy evaluate
        out_decision = self.policy_engine.evaluate(model_output, stage="postllm", detectors=self.detectors, context=context)
        _log(
            {
                "stage": self.OUTPUT_FIREWALL_STAGE,
                "content": model_output,
                "decision": out_decision.to_dict(),
            },
        )

        combined_risk = pre_risk + out_decision.risk_score
        grounding = assess_grounding(model_output, context=context)
        _log(
            {
                "stage": self.OUTPUT_FIREWALL_GROUNDING_STAGE,
                "grounded": grounding.grounded,
                "risk_score": grounding.risk_score,
                "reasons": grounding.reasons,
            },
        )
        risk_eval = score_postllm_risk(
            base_risk=combined_risk,
            model_output=model_output,
            grounding_risk=grounding.risk_score,
            blocked=out_decision.blocked,
        )
        combined_risk = risk_eval.final_risk
        _log(
            {
                "stage": self.OUTPUT_FIREWALL_RISK_STAGE,
                "base_risk": pre_risk + out_decision.risk_score,
                "added_risk": risk_eval.added_risk,
                "final_risk": combined_risk,
                "reasons": risk_eval.reasons,
            },
        )
        if risk_eval.require_approval and not out_decision.blocked:
            out_decision.require_approval = True
            if not out_decision.message:
                out_decision.message = "Post-LLM risk threshold exceeded: approval required"

        combined_message = out_decision.message or pre_message
        pre_sev = self._decision_severity(decision)
        post_sev = self._decision_severity(out_decision)
        if abs(pre_sev - post_sev) >= int(settings.aegis_stage_disagreement_threshold):
            combined_risk += 0.2
            _log(
                {
                    "stage": "consistency.anomaly",
                    "message": "Cross-stage decision disagreement detected",
                    "prellm_severity": pre_sev,
                    "postllm_severity": post_sev,
                    "policy_version": settings.aegis_policy_version,
                    "detector_version": settings.aegis_detector_version,
                    "model_hash": settings.aegis_model_hash,
                },
            )
            risk_state = self._update_and_persist_risk_state(
                session_id,
                risk_state,
                combined_risk,
                injection_signal=False,
                tool_misuse_signal=False,
                goal_drift_signal=True,
            )
            if not out_decision.blocked:
                out_decision.require_approval = True
                if not out_decision.message:
                    out_decision.message = "Consistency anomaly: approval required"
            combined_message = out_decision.message or pre_message

        audit_evidence = build_audit_evidence(
            session_id=session_id,
            request_id=request_id,
            stage=self.OUTPUT_FIREWALL_STAGE,
            risk_score=combined_risk,
            reasons=list(dict.fromkeys(grounding.reasons + risk_eval.reasons)),
            details={
                "prellm_decision": decision.to_dict(),
                "postllm_decision": out_decision.to_dict(),
            },
        )
        _log({"stage": self.OUTPUT_FIREWALL_AUDIT_STAGE, "evidence": audit_evidence})

        if out_decision.require_approval:
            h = approval_hash(stage=self.OUTPUT_FIREWALL_STAGE, content=model_output, context=context)
            if not self.store.is_approved(session_id, h):
                self.store.add_pending_approval(session_id, h)
                combined_actions = list(dict.fromkeys(pre_actions + ["require_approval"]))
                self._update_and_persist_risk_state(
                    session_id,
                    risk_state,
                    combined_risk,
                    injection_signal=False,
                    tool_misuse_signal=False,
                    goal_drift_signal=False,
                )
                refusal = self._policy_block_message(out_decision.message or "Approval required", normalized)
                _log({"stage": self.POSTLLM_RESPONSE_STAGE, "output": refusal, "kind": "approval", "reason": out_decision.message})
                return RuntimeResult(
                    output=refusal,
                    actions=combined_actions,
                    risk_score=combined_risk,
                    message=combined_message,
                    approval_hash=h,
                    metadata={},
                )
        if out_decision.blocked:
            self._update_and_persist_risk_state(
                session_id,
                risk_state,
                combined_risk,
                injection_signal=False,
                tool_misuse_signal=False,
                goal_drift_signal=True,
            )
            refusal = self._policy_block_message(out_decision.message, normalized)
            _log({"stage": self.POSTLLM_RESPONSE_STAGE, "output": refusal, "kind": "block", "reason": out_decision.message})
            return RuntimeResult(
                output=refusal,
                actions=["block"],
                risk_score=combined_risk,
                message=combined_message,
                approval_hash=None,
                metadata={},
            )

        output = self._apply_text_decision(model_output, out_decision)
        if output != model_output:
            _log(
                {
                    "stage": self.OUTPUT_FIREWALL_TRANSFORM_STAGE,
                    "output_original": model_output,
                    "output_transformed": output,
                },
            )

        actions = list(dict.fromkeys(pre_actions + out_decision.actions()))
        if "warn" in actions:
            warning_text = self._policy_warning_message(combined_message, normalized)
            output = f"{warning_text}\n\n{output}".strip()
            _log({"stage": self.POSTLLM_RESPONSE_STAGE, "output": warning_text, "kind": "warn", "reason": combined_message})
        else:
            _log({"stage": self.POSTLLM_RESPONSE_STAGE, "output": output, "kind": "allow", "reason": combined_message})
        llm_flags = context.get("llm_classification") or {}
        updated = self._update_and_persist_risk_state(
            session_id,
            risk_state,
            combined_risk,
            injection_signal=bool(llm_flags.get("prompt_injection") or llm_flags.get("goal_hijack")),
            tool_misuse_signal=False,
            goal_drift_signal=bool(llm_flags.get("goal_hijack", False)),
        )
        _log({"stage": "risk.update", "message_risk": combined_risk, "ood_score": dyn.ood_score, "risk_state": updated})
        return RuntimeResult(
            output=output,
            actions=actions,
            risk_score=combined_risk,
            message=combined_message,
            approval_hash=None,
            metadata={},
        )

    def reload_policies(self):
        self.policy_engine = PolicyEngine(load_policies())

    def guard_tool_call_pre(
        self,
        session_id: str,
        tool_name: str,
        payload: Dict[str, Any],
        environment: Optional[str],
        tenant_id: Optional[str] = None,
        role: Optional[str] = None,
        labels: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        request_id = str(uuid4())
        labels = labels or []
        risk_state = self._get_risk_state(session_id)
        context = {
            "tenant_id": tenant_id,
            "role": role,
            "environment": environment,
            "labels": labels,
            "metadata": {},
            "risk_state": risk_state,
        }

        def _log(event: Dict[str, Any]) -> None:
            payload_event = dict(event)
            payload_event["request_id"] = request_id
            payload_event["flow"] = "tool"
            self.store.log_event(session_id, payload_event)

        if bool(risk_state.get("quarantined", False)) and is_sensitive_tool(tool_name):
            _log(
                {"stage": "tool_pre", "tool": tool_name, "payload": payload, "decision": {"blocked": True, "message": "Tool disabled in quarantine mode"}},
            )
            return {
                "allowed": False,
                "blocked": True,
                "require_approval": False,
                "message": "Tool blocked: session is quarantined",
                "risk_score": 1.0,
                "approval_hash": None,
                "sanitized_payload": None,
            }

        least_privilege = enforce_least_privilege(tool_name, payload, role, environment)
        _log(
            {
                "stage": "tool_least_privilege",
                "tool": tool_name,
                "allowed": least_privilege.allowed,
                "require_approval": least_privilege.require_approval,
                "message": least_privilege.message,
            },
        )
        if not least_privilege.allowed:
            if least_privilege.require_approval:
                h = approval_hash(stage="tool_least_privilege", content=f"{tool_name}:{payload}", context=context)
                if not self.store.is_approved(session_id, h):
                    self.store.add_pending_approval(session_id, h)
                    return {
                        "allowed": False,
                        "blocked": False,
                        "require_approval": True,
                        "message": least_privilege.message,
                        "risk_score": 0.6,
                        "approval_hash": h,
                        "sanitized_payload": None,
                    }
            else:
                self._update_and_persist_risk_state(
                    session_id,
                    risk_state,
                    0.6,
                    injection_signal=False,
                    tool_misuse_signal=is_sensitive_tool(tool_name),
                    goal_drift_signal=False,
                )
                return {
                    "allowed": False,
                    "blocked": True,
                    "require_approval": False,
                    "message": least_privilege.message,
                    "risk_score": 0.6,
                    "approval_hash": None,
                    "sanitized_payload": None,
                }

        pre_decision = self.policy_engine.evaluate(
            text=f"{tool_name}:{payload}",
            stage="tool_pre",
            detectors=self.detectors,
            context=context,
        )
        _log(
            {
                "stage": "tool_pre",
                "tool": tool_name,
                "payload": payload,
                "decision": pre_decision.to_dict(),
            },
        )
        if pre_decision.blocked:
            self._update_and_persist_risk_state(
                session_id,
                risk_state,
                pre_decision.risk_score,
                injection_signal=False,
                tool_misuse_signal=is_sensitive_tool(tool_name),
                goal_drift_signal=False,
            )
            return {
                "allowed": False,
                "blocked": True,
                "require_approval": False,
                "message": pre_decision.message or "Tool blocked",
                "risk_score": pre_decision.risk_score,
                "approval_hash": None,
                "sanitized_payload": None,
            }

        safe_payload = least_privilege.sanitized_payload
        transformed_payload = False
        if pre_decision.redact:
            safe_payload = self._mask_strings(safe_payload, pre_decision.redaction or "[REDACTED]")
            transformed_payload = True
        if pre_decision.modified_text is not None:
            safe_payload = {"modified": pre_decision.modified_text}
            transformed_payload = True
        if transformed_payload:
            _log(
                {
                    "stage": "tool_pre.transform",
                    "tool": tool_name,
                    "payload_original": payload,
                    "payload_transformed": safe_payload,
                },
            )

        tool_modifier = tool_risk_modifier(tool_name)
        risk_weighted = float(pre_decision.risk_score) + float(tool_modifier)
        force_approval = bool(risk_state.get("quarantined", False)) or risk_weighted >= float(settings.aegis_action_risk_approval_threshold)

        if risk_weighted >= float(settings.aegis_action_risk_block_threshold):
            updated = self._update_and_persist_risk_state(
                session_id,
                risk_state,
                risk_weighted,
                injection_signal=False,
                tool_misuse_signal=True,
                goal_drift_signal=False,
            )
            _log(
                {
                    "stage": "tool_risk_fusion",
                    "tool": tool_name,
                    "final_risk": risk_weighted,
                    "tool_risk_modifier": tool_modifier,
                    "decision": "block",
                    "risk_state": updated,
                },
            )
            return {
                "allowed": False,
                "blocked": True,
                "require_approval": False,
                "message": "Tool blocked by action-centric risk policy",
                "risk_score": risk_weighted,
                "approval_hash": None,
                "sanitized_payload": None,
            }

        if pre_decision.require_approval or force_approval:
            h = approval_hash(stage="tool_pre", content=f"{tool_name}:{payload}", context=context)
            if not self.store.is_approved(session_id, h):
                self.store.add_pending_approval(session_id, h)
                _log(
                    {
                        "stage": "tool_risk_fusion",
                        "tool": tool_name,
                        "final_risk": risk_weighted,
                        "tool_risk_modifier": tool_modifier,
                        "decision": "require_approval",
                    },
                )
                return {
                    "allowed": False,
                    "blocked": False,
                    "require_approval": True,
                    "message": pre_decision.message or "Approval required by risk policy",
                    "risk_score": risk_weighted,
                    "approval_hash": h,
                    "sanitized_payload": None,
                }

        return {
            "allowed": True,
            "blocked": False,
            "require_approval": False,
            "message": pre_decision.message,
            "risk_score": risk_weighted,
            "approval_hash": None,
            "sanitized_payload": safe_payload,
        }

    def guard_tool_call_post(
        self,
        session_id: str,
        tool_name: str,
        result: Any,
        environment: Optional[str],
        tenant_id: Optional[str] = None,
        role: Optional[str] = None,
        labels: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        request_id = str(uuid4())
        labels = labels or []
        risk_state = self._get_risk_state(session_id)
        context = {
            "tenant_id": tenant_id,
            "role": role,
            "environment": environment,
            "labels": labels,
            "metadata": {},
            "risk_state": risk_state,
        }

        def _log(event: Dict[str, Any]) -> None:
            payload_event = dict(event)
            payload_event["request_id"] = request_id
            payload_event["flow"] = "tool"
            self.store.log_event(session_id, payload_event)

        result_dict: Any = result
        if self._scan_tool_output_for_injection({"result": result_dict}):
            updated = self._update_and_persist_risk_state(
                session_id,
                risk_state,
                0.8,
                injection_signal=True,
                tool_misuse_signal=is_sensitive_tool(tool_name),
                goal_drift_signal=True,
            )
            _log(
                {
                    "stage": "tool_output_sanitizer",
                    "tool": tool_name,
                    "decision": "block",
                    "message": "Potential prompt injection patterns in tool output",
                    "risk_state": updated,
                },
            )
            return {
                "allowed": False,
                "blocked": True,
                "require_approval": False,
                "message": "Tool output blocked by sanitizer",
                "risk_score": 0.8,
                "approval_hash": None,
                "sanitized_result": None,
            }

        wrapped = f"{tool_name}:<UNTRUSTED_TOOL_DATA>{json.dumps(result_dict, ensure_ascii=True)}</UNTRUSTED_TOOL_DATA>"
        post_decision = self.policy_engine.evaluate(
            text=wrapped,
            stage="tool_post",
            detectors=self.detectors,
            context=context,
        )
        _log(
            {
                "stage": "tool_post",
                "tool": tool_name,
                "result": result_dict,
                "decision": post_decision.to_dict(),
            },
        )
        if post_decision.blocked:
            self._update_and_persist_risk_state(
                session_id,
                risk_state,
                post_decision.risk_score,
                injection_signal=False,
                tool_misuse_signal=is_sensitive_tool(tool_name),
                goal_drift_signal=False,
            )
            return {
                "allowed": False,
                "blocked": True,
                "require_approval": False,
                "message": post_decision.message or "Tool result blocked",
                "risk_score": post_decision.risk_score,
                "approval_hash": None,
                "sanitized_result": None,
            }
        if post_decision.require_approval:
            h = approval_hash(stage="tool_post", content=wrapped, context=context)
            if not self.store.is_approved(session_id, h):
                self.store.add_pending_approval(session_id, h)
                return {
                    "allowed": False,
                    "blocked": False,
                    "require_approval": True,
                    "message": post_decision.message or "Approval required",
                    "risk_score": post_decision.risk_score,
                    "approval_hash": h,
                    "sanitized_result": None,
                }

        safe_result = result_dict
        if post_decision.redact:
            safe_result = self._mask_strings(safe_result, post_decision.redaction or "[REDACTED]")
        if post_decision.modified_text is not None:
            safe_result = {"modified": post_decision.modified_text}
        if safe_result != result_dict:
            _log(
                {
                    "stage": "tool_post.transform",
                    "tool": tool_name,
                    "result_original": result_dict,
                    "result_transformed": safe_result,
                },
            )

        updated = self._update_and_persist_risk_state(
            session_id,
            risk_state,
            max(post_decision.risk_score, tool_risk_modifier(tool_name) * 0.5),
            injection_signal=False,
            tool_misuse_signal=is_sensitive_tool(tool_name),
            goal_drift_signal=False,
        )
        _log(
            {
                "stage": "risk.update.tool",
                "tool": tool_name,
                "final_risk": post_decision.risk_score,
                "risk_state": updated,
            },
        )
        return {
            "allowed": True,
            "blocked": False,
            "require_approval": False,
            "message": post_decision.message,
            "risk_score": post_decision.risk_score,
            "approval_hash": None,
            "sanitized_result": safe_result,
        }

    def handle_tool_call(
        self,
        session_id: str,
        tool_name: str,
        payload: Dict[str, Any],
        environment: Optional[str],
        allowlist: Optional[List[str]],
        denylist: Optional[List[str]],
        filesystem_root: Optional[str],
        tenant_id: Optional[str] = None,
        role: Optional[str] = None,
        labels: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        request_id = str(uuid4())
        labels = labels or []
        risk_state = self._get_risk_state(session_id)
        context = {
            "tenant_id": tenant_id,
            "role": role,
            "environment": environment,
            "labels": labels,
            "metadata": {},
            "risk_state": risk_state,
        }

        def _log(event: Dict[str, Any]) -> None:
            payload_event = dict(event)
            payload_event["request_id"] = request_id
            payload_event["flow"] = "tool"
            self.store.log_event(session_id, payload_event)

        if bool(risk_state.get("quarantined", False)) and is_sensitive_tool(tool_name):
            _log(
                {"stage": "tool_pre", "tool": tool_name, "payload": payload, "decision": {"blocked": True, "message": "Tool disabled in quarantine mode"}},
            )
            return {"allowed": False, "message": "Tool blocked: session is quarantined", "result": None}

        least_privilege = enforce_least_privilege(tool_name, payload, role, environment)
        _log(
            {
                "stage": "tool_least_privilege",
                "tool": tool_name,
                "allowed": least_privilege.allowed,
                "require_approval": least_privilege.require_approval,
                "message": least_privilege.message,
            },
        )
        if not least_privilege.allowed:
            if least_privilege.require_approval:
                h = approval_hash(stage="tool_least_privilege", content=f"{tool_name}:{payload}", context=context)
                if not self.store.is_approved(session_id, h):
                    self.store.add_pending_approval(session_id, h)
                    return {
                        "allowed": False,
                        "message": least_privilege.message,
                        "result": None,
                        "approval_hash": h,
                    }
            else:
                self._update_and_persist_risk_state(
                    session_id,
                    risk_state,
                    0.6,
                    injection_signal=False,
                    tool_misuse_signal=is_sensitive_tool(tool_name),
                    goal_drift_signal=False,
                )
                return {
                    "allowed": False,
                    "message": least_privilege.message,
                    "result": None,
                }

        pre_decision = self.policy_engine.evaluate(
            text=f"{tool_name}:{payload}",
            stage="tool_pre",
            detectors=self.detectors,
            context=context,
        )
        _log(
            {
                "stage": "tool_pre",
                "tool": tool_name,
                "payload": payload,
                "decision": pre_decision.to_dict(),
            },
        )
        if pre_decision.blocked:
            self._update_and_persist_risk_state(
                session_id,
                risk_state,
                pre_decision.risk_score,
                injection_signal=False,
                tool_misuse_signal=is_sensitive_tool(tool_name),
                goal_drift_signal=False,
            )
            return {
                "allowed": False,
                "message": pre_decision.message or "Tool blocked",
                "result": None,
            }

        safe_payload = least_privilege.sanitized_payload
        transformed_payload = False
        if pre_decision.redact:
            safe_payload = self._mask_strings(safe_payload, pre_decision.redaction or "[REDACTED]")
            transformed_payload = True
        if pre_decision.modified_text is not None:
            safe_payload = {"modified": pre_decision.modified_text}
            transformed_payload = True
        if transformed_payload:
            _log(
                {
                    "stage": "tool_pre.transform",
                    "tool": tool_name,
                    "payload_original": payload,
                    "payload_transformed": safe_payload,
                },
            )

        tool_modifier = tool_risk_modifier(tool_name)
        risk_weighted = float(pre_decision.risk_score) + float(tool_modifier)
        force_approval = bool(risk_state.get("quarantined", False)) or risk_weighted >= float(settings.aegis_action_risk_approval_threshold)

        if risk_weighted >= float(settings.aegis_action_risk_block_threshold):
            updated = self._update_and_persist_risk_state(
                session_id,
                risk_state,
                risk_weighted,
                injection_signal=False,
                tool_misuse_signal=True,
                goal_drift_signal=False,
            )
            _log(
                {
                    "stage": "tool_risk_fusion",
                    "tool": tool_name,
                    "final_risk": risk_weighted,
                    "tool_risk_modifier": tool_modifier,
                    "decision": "block",
                    "risk_state": updated,
                },
            )
            return {"allowed": False, "message": "Tool blocked by action-centric risk policy", "result": None}

        if pre_decision.require_approval or force_approval:
            h = approval_hash(stage="tool_pre", content=f"{tool_name}:{payload}", context=context)
            if not self.store.is_approved(session_id, h):
                self.store.add_pending_approval(session_id, h)
                _log(
                    {
                        "stage": "tool_risk_fusion",
                        "tool": tool_name,
                        "final_risk": risk_weighted,
                        "tool_risk_modifier": tool_modifier,
                        "decision": "require_approval",
                    },
                )
                return {
                    "allowed": False,
                    "message": pre_decision.message or "Approval required by risk policy",
                    "result": None,
                    "approval_hash": h,
                }

        try:
            result = execute_tool(
                tool_name=tool_name,
                payload=safe_payload,
                environment=environment,
                allowlist=allowlist,
                denylist=denylist,
                filesystem_root=filesystem_root,
            )
        except Exception as exc:
            if settings.aegis_fail_closed:
                return {
                    "allowed": False,
                    "message": f"Tool execution error: {exc}",
                    "result": None,
                }
            raise
        _log(
            {
                "stage": "tool_exec",
                "tool": tool_name,
                "payload": safe_payload,
                "allowed": result.allowed,
                "message": result.message,
            },
        )
        if result.result and self._scan_tool_output_for_injection(result.result):
            updated = self._update_and_persist_risk_state(
                session_id,
                risk_state,
                max(0.8, risk_weighted),
                injection_signal=True,
                tool_misuse_signal=is_sensitive_tool(tool_name),
                goal_drift_signal=True,
            )
            _log(
                {
                    "stage": "tool_output_sanitizer",
                    "tool": tool_name,
                    "decision": "block",
                    "message": "Potential prompt injection patterns in tool output",
                    "risk_state": updated,
                },
            )
            return {"allowed": False, "message": "Tool output blocked by sanitizer", "result": None}

        wrapped = f"{tool_name}:<UNTRUSTED_TOOL_DATA>{json.dumps(result.result, ensure_ascii=True)}</UNTRUSTED_TOOL_DATA>"
        post_decision = self.policy_engine.evaluate(
            text=wrapped,
            stage="tool_post",
            detectors=self.detectors,
            context=context,
        )
        pre_sev = self._decision_severity(pre_decision)
        post_sev = self._decision_severity(post_decision)
        if abs(pre_sev - post_sev) >= int(settings.aegis_stage_disagreement_threshold):
            _log(
                {
                    "stage": "consistency.anomaly.tool",
                    "tool": tool_name,
                    "message": "Tool stage decision disagreement detected",
                    "tool_pre_severity": pre_sev,
                    "tool_post_severity": post_sev,
                    "policy_version": settings.aegis_policy_version,
                    "detector_version": settings.aegis_detector_version,
                    "model_hash": settings.aegis_model_hash,
                },
            )
            if not post_decision.blocked:
                post_decision.require_approval = True
                post_decision.message = post_decision.message or "Consistency anomaly: approval required"
        _log(
            {
                "stage": "tool_post",
                "tool": tool_name,
                "result": result.result,
                "decision": post_decision.to_dict(),
            },
        )
        if post_decision.blocked:
            self._update_and_persist_risk_state(
                session_id,
                risk_state,
                max(post_decision.risk_score, risk_weighted),
                injection_signal=False,
                tool_misuse_signal=is_sensitive_tool(tool_name),
                goal_drift_signal=False,
            )
            return {
                "allowed": False,
                "message": post_decision.message or "Tool result blocked",
                "result": None,
            }
        if post_decision.require_approval:
            h = approval_hash(stage="tool_post", content=wrapped, context=context)
            if not self.store.is_approved(session_id, h):
                self.store.add_pending_approval(session_id, h)
                return {
                    "allowed": False,
                    "message": post_decision.message or "Approval required",
                    "result": None,
                    "approval_hash": h,
                }

        safe_result = result.result
        if post_decision.redact:
            safe_result = self._mask_strings(safe_result, post_decision.redaction or "[REDACTED]")
        if post_decision.modified_text is not None:
            safe_result = {"modified": post_decision.modified_text}
        if safe_result != result.result:
            _log(
                {
                    "stage": "tool_post.transform",
                    "tool": tool_name,
                    "result_original": result.result,
                    "result_transformed": safe_result,
                },
            )

        updated = self._update_and_persist_risk_state(
            session_id,
            risk_state,
            max(post_decision.risk_score, risk_weighted * 0.5),
            injection_signal=False,
            tool_misuse_signal=is_sensitive_tool(tool_name),
            goal_drift_signal=False,
        )
        _log(
            {
                "stage": "risk.update.tool",
                "tool": tool_name,
                "tool_risk_modifier": tool_modifier,
                "final_risk": risk_weighted,
                "risk_state": updated,
            },
        )

        return {
            "allowed": result.allowed,
            "message": result.message,
            "result": safe_result,
        }

