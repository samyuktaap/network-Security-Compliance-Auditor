"""
CIS (Center for Internet Security) Network Devices Benchmark.
"""

from __future__ import annotations

from sih26155.compliance.policy.models import PolicyRule, PolicySet


def build_cis_policy() -> PolicySet:
    """Returns CIS Benchmark policy rules for network devices."""
    return PolicySet(
        name="cis-network-benchmark",
        rules=[
            PolicyRule(
                control_id="CIS-1.1-SSH",
                description="Ensure SSH Version 2 is enforced.",
                semantic_field="management.ssh.version",
                operator="eq",
                expected=2,
                severity="high",
                frameworks=["CIS", "PCI-DSS", "SOC 2"],
            ),
            PolicyRule(
                control_id="CIS-1.2-TELNET",
                description="Ensure Telnet service is disabled.",
                semantic_field="management.telnet.enabled",
                operator="eq",
                expected=False,
                severity="high",
                frameworks=["CIS", "PCI-DSS", "SOC 2"],
            ),
            PolicyRule(
                control_id="CIS-1.3-HTTP",
                description="Ensure unencrypted HTTP server is disabled.",
                semantic_field="management.http.enabled",
                operator="eq",
                expected=False,
                severity="high",
                frameworks=["CIS", "PCI-DSS", "SOC 2"],
            ),
            PolicyRule(
                control_id="CIS-2.1-LOGIN",
                description="Ensure administrative login failure rate limits are active.",
                semantic_field="authentication.login_protection.enabled",
                operator="eq",
                expected=True,
                severity="medium",
                frameworks=["CIS", "PCI-DSS", "SOC 2"],
            ),
            PolicyRule(
                control_id="CIS-3.1-LOGGING",
                description="Ensure centralized remote syslog is enabled.",
                semantic_field="logging.enabled",
                operator="eq",
                expected=True,
                severity="medium",
                frameworks=["CIS", "PCI-DSS", "SOC 2"],
            ),
        ],
    )
