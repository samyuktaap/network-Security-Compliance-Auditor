"""
Integration tests for API rate limiting headers and security gateway.
"""

import os
from fastapi.testclient import TestClient
import pytest

from sih26155.api.main import app

client = TestClient(app)


def test_rate_limit_headers_present():
    """Verify rate limit tracking headers are returned on API requests."""
    response = client.get("/health")
    assert response.status_code == 200
    assert "x-ratelimit-limit" in response.headers
    assert "x-ratelimit-remaining" in response.headers


def test_security_auth_enforcement_with_key(monkeypatch):
    """Verify security validation when COMPLIANCE_API_KEY is enforced."""
    from sih26155.api.security import verify_api_credentials
    monkeypatch.setenv("COMPLIANCE_API_KEY", "super-secret-token-12345")
    
    # Valid key
    identity = verify_api_credentials(api_key="super-secret-token-12345", bearer=None)
    assert identity.is_authenticated is True

    # Invalid key
    with pytest.raises(Exception):
        verify_api_credentials(api_key="wrong-key", bearer=None)
