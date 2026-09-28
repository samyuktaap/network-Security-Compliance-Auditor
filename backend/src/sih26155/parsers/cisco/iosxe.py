"""
Cisco IOS-XE Parser.

IOS-XE uses the same configuration syntax as IOS for all security-relevant
commands parsed here.  This module re-exports the CiscoIOSParser so the
pipeline can import either name without branching.
"""

from sih26155.parsers.cisco.ios import CiscoIOSParser


class CiscoIOSXEParser(CiscoIOSParser):
    """Cisco IOS-XE parser — identical to IOS for all security controls."""

    @property
    def name(self) -> str:
        return "cisco-iosxe"
