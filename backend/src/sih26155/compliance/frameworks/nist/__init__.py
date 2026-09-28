"""
NIST SP 800-53 Rev 5 Network Device Compliance Framework.
"""

from __future__ import annotations

from sih26155.compliance.policy.models import PolicyRule, PolicySet


def build_nist_policy() -> PolicySet:
    """Returns NIST SP 800-53 Rev 5 network security controls."""
    return PolicySet(
        name="nist-sp-800-53-rev5",
        rules=[
            PolicyRule(
                control_id="NIST-SC-8",
                description="Transmission Confidentiality and Integrity: Telnet must be disabled.",
                semantic_field="management.telnet.enabled",
                operator="eq",
                expected=False,
                severity="high",
                frameworks=["NIST SP 800-53", "ISO/IEC 27001"],
            ),
            PolicyRule(
                control_id="NIST-SC-13",
                description="Cryptographic Protection: SSH must use version 2.",
                semantic_field="management.ssh.version",
                operator="eq",
                expected=2,
                severity="high",
                frameworks=["NIST SP 800-53", "DISA STIG"],
            ),
            PolicyRule(
                control_id="NIST-AC-17",
                description="Remote Access: Cleartext HTTP management disabled.",
                semantic_field="management.http.enabled",
                operator="eq",
                expected=False,
                severity="high",
                frameworks=["NIST SP 800-53"],
            ),
            PolicyRule(
                control_id="NIST-AC-7",
                description="Unsuccessful Logon Attempts: Lockout protection enabled.",
                semantic_field="authentication.login_protection.enabled",
                operator="eq",
                expected=True,
                severity="medium",
                frameworks=["NIST SP 800-53"],
            ),
            PolicyRule(
                control_id="NIST-AU-2",
                description="Event Logging: Central audit log generation enabled.",
                semantic_field="logging.enabled",
                operator="eq",
                expected=True,
                severity="medium",
                frameworks=["NIST SP 800-53"],
            ),
        ],
    )
