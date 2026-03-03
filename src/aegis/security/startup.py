from ..config import settings
from ..policies.loader import load_policies


def _is_prod_env() -> bool:
    return (settings.aegis_env or "").lower() in {"prod", "production"}


def validate_startup_settings() -> None:
    # Always validate policy configuration at startup to avoid silent fail-open.
    policies = load_policies()
    if not policies:
        raise RuntimeError("Startup policy validation failed: no policies loaded.")

    if not _is_prod_env():
        return

    errors: list[str] = []
    if settings.aegis_api_key == "changeme":
        errors.append("AEGIS_API_KEY must not use default 'changeme' in production")
    if settings.jwt_secret == "dev-secret-change":
        errors.append("AEGIS_JWT_SECRET must not use default value in production")
    if len(settings.jwt_secret or "") < 16:
        errors.append("AEGIS_JWT_SECRET must be at least 16 characters in production")
    if not settings.aegis_fail_closed:
        errors.append("AEGIS_FAIL_CLOSED must be true in production")
    if "*" in (settings.aegis_cors_origins or []):
        errors.append("AEGIS_CORS_ORIGINS cannot contain '*' in production")
    if (settings.aegis_rate_limit_backend or "").lower() == "memory":
        errors.append("AEGIS_RATE_LIMIT_BACKEND must not be 'memory' in production")

    if errors:
        raise RuntimeError("Production hardening check failed: " + "; ".join(errors))
