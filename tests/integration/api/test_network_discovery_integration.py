"""
Integration tests for network discovery pipeline, CIDR scanning, and device inventory.
"""

from fastapi.testclient import TestClient
import pytest

from sih26155.api.main import app
from sih26155.discovery.engine import run_discovery_scan

client = TestClient(app)


def test_discovery_demo_lab_integration():
    """Verify lab simulation populates inventory and returns identified devices."""
    response = client.post(
        "/api/network/discover",
        json={"cidr": "192.168.1.0/24", "is_demo": True, "max_hosts": 64},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "COMPLETED"
    assert data["hosts_found"] > 0
    assert any(d["vendor"] in ("Cisco", "Fortinet", "MikroTik") for d in data["devices"])


def test_discovery_inventory_listing():
    """Verify devices endpoint returns populated list."""
    response = client.get("/api/network/devices")
    assert response.status_code == 200
    data = response.json()
    assert "devices" in data
    assert "total" in data


def test_discovery_safe_invalid_cidr():
    """Verify invalid CIDR raises clean HTTP 400 error."""
    response = client.post(
        "/api/network/discover",
        json={"cidr": "invalid-ip-format/99", "is_demo": False},
    )
    assert response.status_code == 400
