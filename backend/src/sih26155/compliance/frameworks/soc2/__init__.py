"""
SOC 2 Type II Network Security & Confidentiality Framework.
"""

from __future__ import annotations

from sih26155.compliance.policy.models import PolicyRule, PolicySet


def build_soc2_policy() -> PolicySet:
    """Returns SOC 2 Type II trust services criteria controls for network infrastructure."""
    return PolicySet(
        name="soc2-type-2",
        rules=[
            PolicyRule(
                control_id="SOC2-CC6.1-AUTH",
                description="Logical Access: Administrative access must enforce multi-factor or hardened SSH authentication.",
                semantic_field="management.ssh.version",
                operator="eq",
                expected=2,
                severity="high",
                frameworks=["SOC 2"],
            ),
            PolicyRule(
                control_id="SOC2-CC6.6-BOUNDARY",
                description="Perimeter Defense: Insecure legacy management protocols (Telnet/HTTP) are prohibited.",
                semantic_field="management.telnet.enabled",
                operator="eq",
                expected=False,
                severity="high",
                frameworks=["SOC 2"],
            ),
            PolicyRule(
                control_id="SOC2-CC6.7-TRANSMIT",
                description="Data Protection: Transmission of credentials across networks must be protected by encryption.",
                semantic_field="management.http.enabled",
                operator="eq",
                expected=False,
                severity="high",
                frameworks=["SOC 2"],
            ),
            PolicyRule(
                control_id="SOC2-CC7.2-LOGGING",
                description="System Monitoring: Network infrastructure must record and transmit security events.",
                semantic_field="logging.enabled",
                operator="eq",
                expected=True,
                severity="medium",
                frameworks=["SOC 2"],
            ),
        ],
    )
