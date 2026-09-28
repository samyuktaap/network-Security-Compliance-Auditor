"""
Juniper Networks Junos OS Device Connector.

Supports Juniper routers, switches, and firewalls with read-only CLI isolation.
"""

from __future__ import annotations

import re
from typing import Any

from sih26155.connectors.base import DeviceConnector, DeviceConnectorError
from sih26155.core.schema.normalized_device import (
    FirewallRuleInfo,
    InterfaceInfo,
    ManagementServiceInfo,
    NormalizedDeviceConfig,
)


class JuniperConnector(DeviceConnector):
    """Safe read-only connector for Juniper Junos appliances."""

    netmiko_device_type = "juniper_junos"

    @property
    def vendor_name(self) -> str:
        return "Juniper"

    @property
    def allowed_commands(self) -> set[str]:
        return {
            "show version",
            "show configuration",
            "show configuration | display set",
            "show interfaces terse",
            "show system services",
            "show route summary",
        }

    def test_connection(self) -> bool:
        """Tests SSH reachability to Juniper device."""
        try:
            from netmiko import ConnectHandler  # type: ignore

            device_params = {
                "device_type": "juniper_junos",
                "host": self.host,
                "username": self.username,
                "password": self.password,
                "port": self.port,
                "conn_timeout": self.timeout,
                "auth_timeout": self.timeout,
            }
            with ConnectHandler(**device_params) as net_connect:
                return bool(net_connect.is_alive())
        except Exception:
            return False

    def collect_configuration(self) -> str:
        """Collects running Junos configuration safely."""
        try:
            from netmiko import ConnectHandler  # type: ignore

            self.validate_command("show configuration")

            device_params = {
                "device_type": "juniper_junos",
                "host": self.host,
                "username": self.username,
                "password": self.password,
                "port": self.port,
                "conn_timeout": self.timeout,
                "auth_timeout": self.timeout,
            }
            with ConnectHandler(**device_params) as net_connect:
                return net_connect.send_command("show configuration")
        except Exception as exc:
            raise DeviceConnectorError(f"Failed to collect Junos config from {self.host}: {exc}") from exc

    def normalize_configuration(self, raw_config: str) -> NormalizedDeviceConfig:
        """Extracts canonical normalized device model from Junos configuration."""
        hostname_match = re.search(r"host-name\s+([^;\s]+);", raw_config)
        hostname = hostname_match.group(1) if hostname_match else self.host

        version_match = re.search(r"version\s+([^;\s]+);", raw_config)
        os_version = f"Junos {version_match.group(1)}" if version_match else "Junos OS"

        interfaces: list[InterfaceInfo] = []
        int_matches = re.finditer(r"interfaces\s*\{\s*([a-zA-Z0-9\/\-]+)", raw_config)
        for m in int_matches:
            interfaces.append(InterfaceInfo(name=m.group(1)))

        cfg_lower = raw_config.lower()
        mgmt = ManagementServiceInfo(
            ssh_enabled="ssh" in cfg_lower,
            ssh_version=2 if "ssh-v2" in cfg_lower or "ssh" in cfg_lower else 1,
            telnet_enabled="telnet" in cfg_lower and "disable" not in cfg_lower,
            http_enabled="http" in cfg_lower and "web-management" in cfg_lower,
            https_enabled="https" in cfg_lower or "web-management { https" in cfg_lower,
            snmp_enabled="snmp" in cfg_lower,
        )

        return NormalizedDeviceConfig(
            id=f"juniper-{self.host.replace('.', '-')}",
            hostname=hostname,
            ip_address=self.host,
            vendor="Juniper",
            device_type="Router / Switch",
            os_version=os_version,
            is_live=True,
            credential_status="authenticated",
            interfaces=interfaces,
            management_services=mgmt,
            firewall_rules=[],
            raw_configuration=raw_config,
        )
