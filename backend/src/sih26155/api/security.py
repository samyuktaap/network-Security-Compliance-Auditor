"""
API Security, Authentication, and Access Control Module.

Provides:
- API Key and Bearer token verification.
- Defense-in-depth protection for compliance analysis and remediation triggers.
- Configurable environment-aware security gating (safe for test harnesses).
"""

from __future__ import annotations

import logging
import os
import secrets
from typing import Optional

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Standard security headers
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
http_bearer = HTTPBearer(auto_error=False)


class SecurityIdentity(BaseModel):
    user_id: str
    role: str
    is_authenticated: bool


def is_security_enforced() -> bool:
    """
    Determines if strict authentication is required.
    Enabled if explicitly configured via SECURITY_ENABLED=true or COMPLIANCE_API_KEY is set.
    """
    flag = os.getenv("SECURITY_ENABLED", "").lower()
    if flag in ("true", "1", "yes"):
        return True
    if os.getenv("COMPLIANCE_API_KEY") or os.getenv("API_KEY"):
        return True
    return False


def get_expected_api_keys() -> set[str]:
    """Retrieves all authorized API keys from environment."""
    keys = set()
    for env_var in ("COMPLIANCE_API_KEY", "API_KEY", "ADMIN_API_KEY"):
        val = os.getenv(env_var)
        if val:
            keys.add(val.strip())
    return keys


def verify_api_credentials(
    api_key: Optional[str] = Security(api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(http_bearer),
) -> SecurityIdentity:
    """
    Validates API authentication via X-API-Key header or Bearer token.
    Raises HTTP 401 if security is enforced and credentials are invalid or missing.
    """
    token = api_key or (bearer.credentials if bearer else None)
    expected_keys = get_expected_api_keys()

    if not is_security_enforced():
        return SecurityIdentity(
            user_id="developer_or_test_agent",
            role="admin",
            is_authenticated=bool(token),
        )

    if not token:
        logger.warning("Unauthenticated request blocked by security gateway.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid 'X-API-Key' header or Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Constant-time comparison against all authorized keys
    is_valid = any(secrets.compare_digest(token, expected) for expected in expected_keys)
    if not is_valid:
        logger.warning("Invalid API token attempt detected.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return SecurityIdentity(
        user_id="authenticated_operator",
        role="admin",
        is_authenticated=True,
    )
