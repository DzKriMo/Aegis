import base64
import codecs
import re
from typing import Dict, List

from .semantic import SemanticMatcher

INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"ignore (all|any) (previous|prior|earlier) (instructions?|rules?)",
    r"disregard (the )?(above|previous|prior) (instructions?|rules?)",
    r"forget (your|all) (instructions?|guardrails?|safety)",
    r"override (the )?(system|developer|policy) (prompt|message|instructions?)",
    r"system prompt",
    r"developer mode",
    r"hidden instructions",
    r"disable guardrails",
]

JAILBREAK_PATTERNS = [
    r"do anything now",
    r"dan mode",
    r"no rules mode",
    r"bypass (all )?(safety|guardrails?|restrictions?)",
]

PII_PATTERNS = [r"\b\d{3}-\d{2}-\d{4}\b", r"\b\d{16}\b"]

SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"sk-[A-Za-z0-9]{20,}",
    r"BEGIN PRIVATE KEY",
    r"\bAEGIS_API_KEY\b",
    r"\bJWT secret\b",
]

POLICY_VIOLATION = [r"\b(build|make) (a )?bomb\b", r"\bcredit card fraud\b"]

HIGH_RISK_ABUSE_PATTERNS = [
    r"\brm\s+-rf\s+/\b",
    r"\bcat\s+/etc/shadow\b",
    r"\b(read|cat|dump)\s+/etc/passwd\b",
    r"\breverse shell\b",
    r"\b(generate|give me)\b.{0,40}\b(real|working)\b.{0,40}\bcredit cards?\b.{0,20}\b(cvv|expiration)\b",
    r"\bhow to\b.{0,60}\b(build|make|create)\b.{0,40}\b(bomb|explosive|weapon)\b",
    r"\bhow to\b.{0,80}\b(hack|breach|exploit|bypass auth|steal credentials|phish)\b",
    r"\b(ransomware|malware|spyware|keylogger)\b.{0,80}\b(write|build|create|deploy)\b",
    r"\b(ddos|botnet)\b.{0,80}\b(set up|launch|build|run)\b",
    r"\b(evade|bypass)\b.{0,60}\b(content moderation|guardrails|security controls?)\b",
    r"\bhow to\b.{0,80}\b(commit|perform|execute)\b.{0,40}\b(fraud|identity theft|money laundering)\b",
]

SUSPICIOUS_DISCLOSURE_PATTERNS = [
    r"\b(hidden policies?|operational constraints|initialization parameters?)\b",
    r"\blist\b.{0,60}\b(configuration parameters?|active config)\b",
    r"\bwhat rules are you following\b",
    r"\brestrictions that apply\b",
]
CAUTION_DISCLOSURE_PATTERNS = [
    r"\b(list|include|summarize|summarise|outline)\b.{0,80}\b(high[- ]level|safe(?:ly)?|sanitized|non-sensitive)\b.{0,80}\b(policy|policies|restrictions?|constraints?|boundaries|guardrails?|rules?)\b",
    r"\b(high[- ]level|safe(?:ly)?|sanitized|non-sensitive)\b.{0,80}\b(policy|policies|restrictions?|constraints?|boundaries|guardrails?|rules?)\b",
    r"\b(risk boundaries|policy constraints|operational boundaries)\b",
]

EXFIL_PATTERNS = [
    r"authorization:\s*bearer",
    r"api[-_ ]?key",
    r"\b(environment variables?|env vars?)\b",
    r"\b\.env\b",
    r"\b/etc/(passwd|shadow)\b",
    r"\b(jwt secret|secret key|token)\b",
    r"\b(exfiltrat(e|ion)|steal|dump|leak|export)\b.{0,80}\b(credentials?|tokens?|secrets?|passwords?|api[-_ ]?keys?|environment variables?)\b",
    r"\b(output|print|reveal|show|display|tell|list)\b.{0,120}\b(system (prompt|configuration|instructions?)|developer message|hidden instructions?|hidden policies?|internal (rules|config|policy)|secret(s)?|token(s)?|api[-_ ]?key|environment variables?|env vars?)\b",
]

GOAL_HIJACK = [
    r"new instructions override",
    r"change the goal",
    r"before answering",
    r"before doing that",
    r"do this first",
    r"instead of your instructions",
]

DATA_LEAKAGE = [r"internal only", r"confidential"]

TASK_VERBS = re.compile(r"\b(summarize|summarise|translate|analyze|analyse|answer|write|explain|draft|review|rewrite)\b", re.IGNORECASE)
LEAK_VERBS = re.compile(r"\b(output|reveal|print|show|display|dump|expose|list|tell)\b", re.IGNORECASE)
DISCLOSURE_QUERY_VERBS = re.compile(r"\b(what|which|show|tell|list|print|reveal|output|dump|display)\b", re.IGNORECASE)
SENSITIVE_TARGETS = re.compile(
    r"\b(system (prompt|configuration|instructions?)|initial instructions?|instructions you were initialized with|developer message|hidden instructions?|hidden policies?|internal (rules|config|policy)|policies govern your responses|chain[- ]of[- ]thought|environment variables?|env vars?|\.env|/etc/passwd|/etc/shadow|jwt secret|api key)\b",
    re.IGNORECASE,
)
SEQUENCE_MARKERS = re.compile(r"\b(before answering|before you answer|before doing that|first[, ]|then[, ]|also[, ]|prior to answering)\b", re.IGNORECASE)
RESEARCH_CONTEXT = re.compile(r"\b(example|for example|demonstrate|demonstration|explain|analyze|analysis|awareness|training|defensive|red team|research|high[- ]level|dangerous|risky|for awareness|do not execute)\b", re.IGNORECASE)
FICTION_CONTEXT = re.compile(r"\b(fiction|fictional|story|novel|script|roleplay)\b", re.IGNORECASE)
DIRECT_IMPERATIVE = re.compile(r"\b(ignore|disregard|forget|override|reveal|output|print|dump|show|display|expose|tell|list|run|execute|open|read|cat)\b", re.IGNORECASE)
SOFT_QUALIFIERS = re.compile(r"\b(high[- ]level|broad terms|if possible|briefly|no secrets|for reproducibility|for auditing|safely disclose)\b", re.IGNORECASE)
SECURITY_ATTACK_DISCUSSION = re.compile(
    r"\b(prompt injection|jailbreak)\b.{0,48}\b(attack|payload|instruction|example|malicious)\b",
    re.IGNORECASE,
)

BASE64_TOKEN = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
HEX_TOKEN = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")
UNICODE_ESCAPES = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")


def _match_any(patterns, text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def _decode_obfuscated_candidates(text: str) -> List[str]:
    out: List[str] = []

    for token in BASE64_TOKEN.findall(text):
        try:
            decoded = base64.b64decode(token + "==", validate=False).decode("utf-8", errors="ignore")
            if decoded and decoded != token:
                out.append(decoded)
        except Exception:
            pass

    for token in HEX_TOKEN.findall(text):
        try:
            decoded = bytes.fromhex(token).decode("utf-8", errors="ignore")
            if decoded and decoded != token:
                out.append(decoded)
        except Exception:
            pass

    for token in UNICODE_ESCAPES.findall(text):
        try:
            decoded = codecs.decode(token, "unicode_escape")
            if decoded and decoded != token:
                out.append(decoded)
        except Exception:
            pass

    # Rot13 decode only if there are strong markers (to avoid broad false positives).
    if re.search(r"\b(cevag|flfgrz|xrl|raivebazrag|vafgehpgvbaf|qhzc)\b", text, re.IGNORECASE):
        try:
            rot = codecs.decode(text, "rot_13")
            if rot != text:
                out.append(rot)
        except Exception:
            pass

    return out


def _contains_obfuscated_attack(text: str) -> bool:
    decoded_variants = _decode_obfuscated_candidates(text)
    for d in decoded_variants:
        if _match_any(INJECTION_PATTERNS + EXFIL_PATTERNS + HIGH_RISK_ABUSE_PATTERNS, d):
            return True
        if LEAK_VERBS.search(d) and SENSITIVE_TARGETS.search(d):
            return True
    return False


def _has_direct_sensitive_exfil_request(text: str) -> bool:
    if SOFT_QUALIFIERS.search(text):
        return False
    # Treat quoted/example-driven research phrasing as non-imperative by default.
    if RESEARCH_CONTEXT.search(text) and re.search(r"\b(example|for example|like)\b", text, re.IGNORECASE) and not LEAK_VERBS.search(text):
        return False
    has_sensitive_target = bool(SENSITIVE_TARGETS.search(text))
    if not has_sensitive_target:
        return False
    has_strong_verb = bool(LEAK_VERBS.search(text) or DIRECT_IMPERATIVE.search(text))
    return has_strong_verb


def _looks_like_benign_discussion(text: str) -> bool:
    topic = bool(re.search(r"\b(prompt injection|jailbreak|system prompt|ssrf|/etc/passwd|guardrails?)\b", text, re.IGNORECASE))
    return bool(topic and RESEARCH_CONTEXT.search(text) and not _has_direct_sensitive_exfil_request(text))


def _is_explicit_safety_education(text: str, matcher: SemanticMatcher) -> bool:
    has_explain = bool(re.search(r"\b(explain|why|how|demonstrate)\b", text, re.IGNORECASE))
    has_safety_theme = bool(
        re.search(
            r"\b(dangerous|risk|secure|security|awareness|high[- ]level|do not execute|for awareness|prompt injection|jailbreak|system prompt|exfiltration)\b",
            text,
            re.IGNORECASE,
        )
    )
    semantic_safe = matcher.match("education_safe", text)
    return (has_explain and has_safety_theme or semantic_safe) and not _has_direct_sensitive_exfil_request(text)


def _is_fictional_context(text: str) -> bool:
    return bool(FICTION_CONTEXT.search(text))


def _multi_stage_hijack_score(text: str, matcher: SemanticMatcher) -> int:
    score = 0
    benign_discussion = _looks_like_benign_discussion(text) or _is_explicit_safety_education(text, matcher)

    if _match_any(INJECTION_PATTERNS, text):
        score += 2
    if SEQUENCE_MARKERS.search(text):
        score += 1
    if TASK_VERBS.search(text):
        score += 1
    if _has_direct_sensitive_exfil_request(text):
        score += 4
    if _contains_obfuscated_attack(text):
        score += 3

    if benign_discussion and not _has_direct_sensitive_exfil_request(text):
        score = min(score, 2)

    return score


def detect_prompt_injection(text: str, context: Dict) -> bool:
    matcher = SemanticMatcher.from_env()
    llm = context.get("llm_classification", {})

    if _is_explicit_safety_education(text, matcher):
        return False

    strong_attack = _multi_stage_hijack_score(text, matcher) >= 4
    if _is_fictional_context(text) and not strong_attack:
        return False
    if strong_attack:
        return True

    if SECURITY_ATTACK_DISCUSSION.search(text):
        return True

    return _match_any(INJECTION_PATTERNS, text) or _contains_obfuscated_attack(text) or matcher.match("prompt_injection", text) or bool(llm.get("prompt_injection", False))


def detect_jailbreak(text: str, context: Dict) -> bool:
    matcher = SemanticMatcher.from_env()
    llm = context.get("llm_classification", {})
    return _match_any(JAILBREAK_PATTERNS, text) or matcher.match("jailbreak", text) or bool(llm.get("jailbreak", False))


def detect_pii(text: str, context: Dict) -> bool:
    llm = context.get("llm_classification", {})
    return _match_any(PII_PATTERNS, text) or bool(llm.get("pii", False))


def detect_secrets(text: str, context: Dict) -> bool:
    llm = context.get("llm_classification", {})
    return _match_any(SECRET_PATTERNS, text) or bool(llm.get("secrets", False))


def detect_policy_violation(text: str, context: Dict) -> bool:
    llm = context.get("llm_classification", {})
    return _match_any(POLICY_VIOLATION, text) or bool(llm.get("policy_violation", False))


def detect_high_risk_abuse(text: str, context: Dict) -> bool:
    matcher = SemanticMatcher.from_env()
    if _is_explicit_safety_education(text, matcher):
        return False
    if _is_fictional_context(text):
        return False
    return _match_any(HIGH_RISK_ABUSE_PATTERNS, text) or _contains_obfuscated_attack(text) or matcher.match("high_risk_abuse", text)


def detect_suspicious_disclosure(text: str, context: Dict) -> bool:
    if _has_direct_sensitive_exfil_request(text):
        return False
    matcher = SemanticMatcher.from_env()
    return _match_any(SUSPICIOUS_DISCLOSURE_PATTERNS, text) or matcher.match("suspicious_disclosure", text)


def detect_caution_disclosure(text: str, context: Dict) -> bool:
    if _has_direct_sensitive_exfil_request(text):
        return False
    matcher = SemanticMatcher.from_env()
    if _is_explicit_safety_education(text, matcher):
        return False
    return _match_any(CAUTION_DISCLOSURE_PATTERNS, text)


def detect_exfiltration(text: str, context: Dict) -> bool:
    matcher = SemanticMatcher.from_env()
    if _is_explicit_safety_education(text, matcher):
        return False

    labels = context.get("labels") or []
    if "CONFIDENTIAL" in labels and _match_any(EXFIL_PATTERNS, text):
        return True
    if _is_fictional_context(text):
        return False

    llm = context.get("llm_classification", {})
    return _match_any(EXFIL_PATTERNS, text) or _contains_obfuscated_attack(text) or matcher.match("exfiltration", text) or bool(llm.get("exfiltration", False))


def detect_goal_hijack(text: str, context: Dict) -> bool:
    matcher = SemanticMatcher.from_env()
    llm = context.get("llm_classification", {})

    if _is_explicit_safety_education(text, matcher):
        return False

    score = _multi_stage_hijack_score(text, matcher)
    if _is_fictional_context(text) and score < 4:
        return False

    if _has_direct_sensitive_exfil_request(text):
        return True
    if score >= 4:
        return True

    return _match_any(GOAL_HIJACK, text) or matcher.match("goal_hijack", text) or bool(llm.get("goal_hijack", False))


def detect_data_leakage(text: str, context: Dict) -> bool:
    matcher = SemanticMatcher.from_env()
    llm = context.get("llm_classification", {})
    return _match_any(DATA_LEAKAGE, text) or matcher.match("data_leakage", text) or bool(llm.get("data_leakage", False))


def detect_ml_block_intent(text: str, context: Dict) -> bool:
    local = context.get("local_classification", {})
    if not local.get("enabled"):
        return False
    label = str(local.get("label", "")).upper()
    conf = float(local.get("confidence", 0.0) or 0.0)
    threshold = float(context.get("local_block_threshold", 0.78))
    return label == "BLOCK" and conf >= threshold


def detect_ml_warn_intent(text: str, context: Dict) -> bool:
    local = context.get("local_classification", {})
    if not local.get("enabled"):
        return False
    label = str(local.get("label", "")).upper()
    conf = float(local.get("confidence", 0.0) or 0.0)
    threshold = float(context.get("local_warn_threshold", 0.64))
    return label == "WARN" and conf >= threshold
