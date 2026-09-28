"""
Compliance Framework Factory & Unified Resolver.
"""

from __future__ import annotations

from sih26155.compliance.frameworks.cis import build_cis_policy
from sih26155.compliance.frameworks.iso27001 import build_iso27001_policy
from sih26155.compliance.frameworks.nist import build_nist_policy
from sih26155.compliance.frameworks.pcidss import build_pcidss_policy
from sih26155.compliance.frameworks.soc2 import build_soc2_policy
from sih26155.compliance.frameworks.stig import build_stig_policy
from sih26155.compliance.policy.models import PolicySet

_FRAMEWORK_BUILDERS = {
    "cis": build_cis_policy,
    "iso27001": build_iso27001_policy,
    "nist": build_nist_policy,
    "stig": build_stig_policy,
    "disa_stig": build_stig_policy,
    "pcidss": build_pcidss_policy,
    "pci_dss": build_pcidss_policy,
    "soc2": build_soc2_policy,
}


def get_framework_policy(framework_name: str) -> PolicySet:
    """
    Returns the standard PolicySet for the specified compliance standard.
    Defaults to CIS benchmark if name is not recognized.
    """
    key = framework_name.strip().lower().replace("-", "_").replace(" ", "_")
    builder = _FRAMEWORK_BUILDERS.get(key, build_cis_policy)
    return builder()


def list_supported_frameworks() -> list[str]:
    """Returns all currently supported enterprise compliance framework identifiers."""
    return ["CIS", "ISO 27001", "NIST SP 800-53", "DISA STIG", "PCI-DSS v4.0", "SOC 2 Type II"]
