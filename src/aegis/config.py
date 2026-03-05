import os
from dotenv import load_dotenv

load_dotenv()


def _get(name: str, default: str | None = None) -> str | None:
    return os.getenv(name, default)


def _get_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y"}


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _get_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _get_list(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name)
    if raw is None:
        return default
    items = [item.strip() for item in raw.split(",")]
    return [item for item in items if item]


class Settings:
    def __init__(self):
        self.aegis_env = _get("AEGIS_ENV", "dev")
        self.aegis_guardrail_profile = (_get("AEGIS_GUARDRAIL_PROFILE", "balanced") or "balanced").strip().lower()
        self.database_url = _get("DATABASE_URL", "sqlite:///aegis.db")
        self.aegis_api_key = _get("AEGIS_API_KEY", "changeme")
        self.aegis_fail_closed = _get_bool("AEGIS_FAIL_CLOSED", False)
        self.aegis_strict_policy_load = _get_bool("AEGIS_STRICT_POLICY_LOAD", True)
        self.policy_path = _get("POLICY_PATH", "config/policies.example.yaml")
        self.aegis_semantic_enabled = _get_bool("AEGIS_SEMANTIC_ENABLED", False)
        self.aegis_embed_model = _get("AEGIS_EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
        self.aegis_db_enabled = _get_bool("AEGIS_DB_ENABLED", True)
        self.aegis_llm_enabled = _get_bool("AEGIS_LLM_ENABLED", False)
        self.aegis_llm_endpoint = _get("AEGIS_LLM_ENDPOINT", "http://127.0.0.1:8080/v1/chat/completions")
        self.aegis_llm_timeout = _get_int("AEGIS_LLM_TIMEOUT", 12)
        self.aegis_llm_model = _get("AEGIS_LLM_MODEL", "qwen2.5-3b-instruct")
        self.aegis_model_enabled = _get_bool("AEGIS_MODEL_ENABLED", False)
        self.aegis_model_endpoint = _get("AEGIS_MODEL_ENDPOINT", self.aegis_llm_endpoint)
        self.aegis_model_timeout = _get_int("AEGIS_MODEL_TIMEOUT", 30)
        self.aegis_model_name = _get("AEGIS_MODEL_NAME", self.aegis_llm_model)
        self.aegis_model_max_tokens = _get_int("AEGIS_MODEL_MAX_TOKENS", 500)
        self.aegis_model_system_prompt = _get(
            "AEGIS_MODEL_SYSTEM_PROMPT",
            "You are a concise and safe assistant. Refuse harmful requests and prioritize secure behavior.",
        )
        self.aegis_local_classifier_enabled = _get_bool("AEGIS_LOCAL_CLASSIFIER_ENABLED", False)
        self.aegis_local_classifier_path = _get("AEGIS_LOCAL_CLASSIFIER_PATH", "models/guardrail_nb.json")
        self.aegis_local_block_threshold = _get_float("AEGIS_LOCAL_BLOCK_THRESHOLD", 0.78)
        self.aegis_local_warn_threshold = _get_float("AEGIS_LOCAL_WARN_THRESHOLD", 0.64)
        self.aegis_telemetry_enabled = _get_bool("AEGIS_TELEMETRY_ENABLED", True)
        self.aegis_telemetry_path = _get("AEGIS_TELEMETRY_PATH", "")
        self.jwt_secret = _get("AEGIS_JWT_SECRET", "dev-secret-change")
        self.jwt_issuer = _get("AEGIS_JWT_ISSUER", "aegis")
        self.jwt_exp_minutes = _get_int("AEGIS_JWT_EXP_MINUTES", 120)
        self.otel_enabled = _get_bool("AEGIS_OTEL_ENABLED", False)
        self.aegis_cors_origins = _get_list("AEGIS_CORS_ORIGINS", ["*"])
        self.aegis_rate_limit_backend = _get("AEGIS_RATE_LIMIT_BACKEND", "memory")
        self.aegis_rate_limit_limit = _get_int("AEGIS_RATE_LIMIT_LIMIT", 60)
        self.aegis_rate_limit_window_seconds = _get_int("AEGIS_RATE_LIMIT_WINDOW_SECONDS", 60)
        self.aegis_rate_limit_sqlite_path = _get("AEGIS_RATE_LIMIT_SQLITE_PATH", "aegis_rate_limit.db")
        self.aegis_rate_limit_redis_url = _get("AEGIS_RATE_LIMIT_REDIS_URL", "redis://127.0.0.1:6379/0")
        self.aegis_rate_limit_redis_prefix = _get("AEGIS_RATE_LIMIT_REDIS_PREFIX", "aegis:ratelimit")
        self.aegis_local_appeal_llm_enabled = _get_bool("AEGIS_LOCAL_APPEAL_LLM_ENABLED", False)
        self.aegis_local_appeal_conf_threshold = _get_float("AEGIS_LOCAL_APPEAL_CONF_THRESHOLD", 0.62)
        self.aegis_quarantine_threshold = _get_float("AEGIS_QUARANTINE_THRESHOLD", 0.95)
        self.aegis_ood_warn_threshold = _get_float("AEGIS_OOD_WARN_THRESHOLD", 0.72)
        self.aegis_action_risk_approval_threshold = _get_float("AEGIS_ACTION_RISK_APPROVAL_THRESHOLD", 0.75)
        self.aegis_action_risk_block_threshold = _get_float("AEGIS_ACTION_RISK_BLOCK_THRESHOLD", 1.1)
        self.aegis_stage_disagreement_threshold = _get_int("AEGIS_STAGE_DISAGREEMENT_THRESHOLD", 2)
        self.aegis_policy_version = _get("AEGIS_POLICY_VERSION", "v1")
        self.aegis_detector_version = _get("AEGIS_DETECTOR_VERSION", "v1")
        self.aegis_model_hash = _get("AEGIS_MODEL_HASH", "unknown")
        self._apply_guardrail_profile()

    def _apply_guardrail_profile(self) -> None:
        profile = self.aegis_guardrail_profile
        if profile == "strict":
            # Lower thresholds => more conservative enforcement.
            self.aegis_local_block_threshold = min(self.aegis_local_block_threshold, 0.72)
            self.aegis_local_warn_threshold = min(self.aegis_local_warn_threshold, 0.58)
            self.aegis_fail_closed = True
            self.aegis_semantic_enabled = True
        elif profile == "assist":
            # Higher thresholds => lower friction for benign assistant usage.
            self.aegis_local_block_threshold = max(self.aegis_local_block_threshold, 0.86)
            self.aegis_local_warn_threshold = max(self.aegis_local_warn_threshold, 0.72)
        else:
            # "balanced" default: no overrides.
            self.aegis_guardrail_profile = "balanced"


settings = Settings()
