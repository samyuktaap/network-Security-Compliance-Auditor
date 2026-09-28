"""
DoD DISA STIG Network Device Security Requirements Guide (SRG).
"""

from __future__ import annotations

from sih26155.compliance.policy.models import PolicyRule, PolicySet


def build_stig_policy() -> PolicySet:
    """Returns DISA STIG network controls."""
    return PolicySet(
        name="disa-stig-network-srg",
        rules=[
            PolicyRule(
                control_id="STIG-NET-000018",
                description="The network device must not use unencrypted Telnet for device administration.",
                semantic_field="management.telnet.enabled",
                operator="eq",
                expected=False,
                severity="high",
                frameworks=["DISA STIG"],
            ),
            PolicyRule(
                control_id="STIG-NET-000019",
                description="The network device must implement SSHv2 using FIPS-approved ciphers.",
                semantic_field="management.ssh.version",
                operator="eq",
                expected=2,
                severity="high",
                frameworks=["DISA STIG"],
            ),
            PolicyRule(
                control_id="STIG-NET-000074",
                description="The network device must automatically terminate or lock out accounts after 3 consecutive failed login attempts.",
                semantic_field="authentication.login_protection.enabled",
                operator="eq",
                expected=True,
                severity="medium",
                frameworks=["DISA STIG"],
            ),
            PolicyRule(
                control_id="STIG-NET-000131",
                description="The network device must forward security audit records to a centralized syslog server.",
                semantic_field="logging.enabled",
                operator="eq",
                expected=True,
                severity="medium",
                frameworks=["DISA STIG"],
            ),
        ],
    )
