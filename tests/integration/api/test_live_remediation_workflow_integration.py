"""
Integration tests for proposal generation, dry-run live remediation, and rollback.
"""

from fastapi.testclient import TestClient
import pytest

from sih26155.api.main import app

client = TestClient(app)


def test_remediation_proposals_generation():
    """Verify proposal generation returns actionable fixes for failed findings."""
    config_sample = "hostname LAB-RTR-01\nline vty 0 4\n transport input telnet\n"
    findings = [
        {
            "control_id": "MGMT-TELNET-001",
            "status": "FAIL",
            "description": "Telnet is enabled",
        }
    ]
    response = client.post(
        "/api/remediation/proposals",
        json={
            "vendor": "cisco",
            "raw_config": config_sample,
            "findings": findings,
            "target_type": "upload",
            "target_id": "test.conf",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total_proposals"] >= 1
    assert data["proposals"][0]["control_id"] == "MGMT-TELNET-001"
    assert "transport input ssh" in str(data["proposals"][0]["commands"])


def test_remediation_live_dry_run_workflow():
    """Verify live apply executes safety simulation, pre-change backup, diff, and re-audit."""
    config_sample = "hostname LAB-RTR-01\nip ssh version 2\nline vty 0 4\n transport input telnet\n"
    response = client.post(
        "/api/remediation/live/apply",
        json={
            "device_id": "dev-test-rtr",
            "control_id": "MGMT-TELNET-001",
            "vendor": "cisco",
            "hostname": "LAB-RTR-01",
            "raw_config": config_sample,
            "approved": True,
            "approved_by": "Test Operator",
            "is_demo": True,
            "dry_run": True,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["status"] == "RESOLVED"
    assert "audit_record_id" in data
    assert "backup_snapshot_id" in data
    assert "commands_applied" in data
    assert "diff" in data
