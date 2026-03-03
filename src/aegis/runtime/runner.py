from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import json
import re

from ..policies.engine import PolicyEngine
from ..policies.loader import load_policies
from ..detectors.registry import DetectorRegistry
from ..detectors.llm_client import classify_text
from ..detectors.local_classifier import classify_guardrail_label
from ..prellm.normalize import normalize_text
from ..prellm.network import evaluate_urls
from ..postllm.approval import approval_hash
from ..config import settings
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

        # 0) normalize input
        normalized, norm_flags = normalize_text(content)
        if norm_flags:
            self.store.log_event(
                session_id,
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
        self.store.log_event(
            session_id,
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
        self.store.log_event(
            session_id,
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
            self.store.log_event(
                session_id,
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
                return RuntimeResult(
                    output=net_decision.message or "Blocked",
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
        self.store.log_event(
            session_id,
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
            return RuntimeResult(
                output=decision.message or "Blocked",
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
                return RuntimeResult(
                    output=decision.message or "Approval required",
                    actions=["require_approval"],
                    risk_score=decision.risk_score,
                    message=decision.message,
                    approval_hash=h,
                    metadata={},
                )

        pre_actions = [a for a in decision.actions() if a not in {"block", "require_approval"}]
        pre_risk = decision.risk_score
        pre_message = decision.message

        # 4) placeholder model response
        # Use a neutral stub to avoid benchmarking artifacts from echoing raw input.
        model_output = "Processed safely by upstream model."

        # 5) post-LLM policy evaluate
        out_decision = self.policy_engine.evaluate(model_output, stage="postllm", detectors=self.detectors, context=context)
        self.store.log_event(
            session_id,
            {
                "stage": "postllm",
                "content": model_output,
                "decision": out_decision.to_dict(),
            },
        )

        combined_risk = pre_risk + out_decision.risk_score
        combined_message = out_decision.message or pre_message

        if out_decision.require_approval:
            h = approval_hash(stage="postllm", content=model_output, context=context)
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
                return RuntimeResult(
                    output=out_decision.message or "Approval required",
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
            return RuntimeResult(
                output=out_decision.message or "Blocked",
                actions=["block"],
                risk_score=combined_risk,
                message=combined_message,
                approval_hash=None,
                metadata={},
            )

        output = out_decision.apply_redaction(model_output)
        if out_decision.modified_text is not None:
            output = out_decision.modified_text

        actions = list(dict.fromkeys(pre_actions + out_decision.actions()))
        llm_flags = context.get("llm_classification") or {}
        updated = self._update_and_persist_risk_state(
            session_id,
            risk_state,
            combined_risk,
            injection_signal=bool(llm_flags.get("prompt_injection") or llm_flags.get("goal_hijack")),
            tool_misuse_signal=False,
            goal_drift_signal=bool(llm_flags.get("goal_hijack", False)),
        )
        self.store.log_event(
            session_id,
            {"stage": "risk.update", "message_risk": combined_risk, "ood_score": dyn.ood_score, "risk_state": updated},
        )
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
        if bool(risk_state.get("quarantined", False)) and is_sensitive_tool(tool_name):
            self.store.log_event(
                session_id,
                {"stage": "tool_pre", "tool": tool_name, "payload": payload, "decision": {"blocked": True, "message": "Tool disabled in quarantine mode"}},
            )
            return {"allowed": False, "message": "Tool blocked: session is quarantined", "result": None}

        pre_decision = self.policy_engine.evaluate(
            text=f"{tool_name}:{payload}",
            stage="tool_pre",
            detectors=self.detectors,
            context=context,
        )
        self.store.log_event(
            session_id,
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
            self.store.log_event(
                session_id,
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
                self.store.log_event(
                    session_id,
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
                payload=payload,
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
        self.store.log_event(
            session_id,
            {
                "stage": "tool_exec",
                "tool": tool_name,
                "payload": payload,
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
            self.store.log_event(
                session_id,
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
        self.store.log_event(
            session_id,
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
        updated = self._update_and_persist_risk_state(
            session_id,
            risk_state,
            max(post_decision.risk_score, risk_weighted * 0.5),
            injection_signal=False,
            tool_misuse_signal=is_sensitive_tool(tool_name),
            goal_drift_signal=False,
        )
        self.store.log_event(
            session_id,
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
            "result": result.result,
        }

