"""
PCI-DSS v4.0 Network Security Controls.
"""

from __future__ import annotations

from sih26155.compliance.policy.models import PolicyRule, PolicySet


def build_pcidss_policy() -> PolicySet:
    """Returns PCI-DSS v4.0 network security compliance rules."""
    return PolicySet(
        name="pci-dss-v4.0",
        rules=[
            PolicyRule(
                control_id="PCI-REQ-1.2.5",
                description="Requirement 1: Non-console administrative access must use strong cryptography (SSHv2, HTTPS).",
                semantic_field="management.ssh.version",
                operator="eq",
                expected=2,
                severity="high",
                frameworks=["PCI-DSS"],
            ),
            PolicyRule(
                control_id="PCI-REQ-2.2.3",
                description="Requirement 2: Insecure protocols including cleartext Telnet and HTTP must be disabled.",
                semantic_field="management.telnet.enabled",
                operator="eq",
                expected=False,
                severity="high",
                frameworks=["PCI-DSS"],
            ),
            PolicyRule(
                control_id="PCI-REQ-8.3.4",
                description="Requirement 8: User accounts must be locked out after not more than 10 failed login attempts.",
                semantic_field="authentication.login_protection.enabled",
                operator="eq",
                expected=True,
                severity="medium",
                frameworks=["PCI-DSS"],
            ),
            PolicyRule(
                control_id="PCI-REQ-10.2.1",
                description="Requirement 10: Audit logs must be recorded and transmitted to centralized log servers.",
                semantic_field="logging.enabled",
                operator="eq",
                expected=True,
                severity="medium",
                frameworks=["PCI-DSS"],
            ),
        ],
    )
