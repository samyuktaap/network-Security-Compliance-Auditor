"""
Arista Networks EOS Device Connector.

Supports Arista EOS switches and routers with read-only CLI isolation.
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


class AristaConnector(DeviceConnector):
    """Safe read-only connector for Arista EOS appliances."""

    netmiko_device_type = "arista_eos"

    @property
    def vendor_name(self) -> str:
        return "Arista"

    @property
    def allowed_commands(self) -> set[str]:
        return {
            "show version",
            "show running-config",
            "show interfaces status",
            "show ip interface brief",
            "show management api http-commands",
            "show ip route summary",
        }

    def test_connection(self) -> bool:
        """Tests SSH reachability to Arista EOS device."""
        try:
            from netmiko import ConnectHandler  # type: ignore

            device_params = {
                "device_type": "arista_eos",
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
        """Collects running EOS configuration safely."""
        try:
            from netmiko import ConnectHandler  # type: ignore

            self.validate_command("show running-config")

            device_params = {
                "device_type": "arista_eos",
                "host": self.host,
                "username": self.username,
                "password": self.password,
                "port": self.port,
                "conn_timeout": self.timeout,
                "auth_timeout": self.timeout,
            }
            with ConnectHandler(**device_params) as net_connect:
                return net_connect.send_command("show running-config")
        except Exception as exc:
            raise DeviceConnectorError(f"Failed to collect Arista EOS config from {self.host}: {exc}") from exc

    def normalize_configuration(self, raw_config: str) -> NormalizedDeviceConfig:
        """Extracts canonical normalized device model from Arista EOS configuration."""
        hostname_match = re.search(r"hostname\s+([^\s\n]+)", raw_config)
        hostname = hostname_match.group(1) if hostname_match else self.host

        version_match = re.search(r"Software\s+image\s+version:\s*([^\n\r]+)", raw_config)
        os_version = f"EOS {version_match.group(1)}" if version_match else "Arista EOS"

        interfaces: list[InterfaceInfo] = []
        for m in re.finditer(r"interface\s+([A-Za-z0-9\/\.\-]+)", raw_config):
            interfaces.append(InterfaceInfo(name=m.group(1)))

        cfg_lower = raw_config.lower()
        mgmt = ManagementServiceInfo(
            ssh_enabled="ssh" in cfg_lower or "management ssh" in cfg_lower,
            ssh_version=2,
            telnet_enabled="telnet" in cfg_lower and "no management telnet" not in cfg_lower,
            http_enabled="protocol http" in cfg_lower,
            https_enabled="protocol https" in cfg_lower or "management api http-commands" in cfg_lower,
            snmp_enabled="snmp-server" in cfg_lower,
        )

        return NormalizedDeviceConfig(
            id=f"arista-{self.host.replace('.', '-')}",
            hostname=hostname,
            ip_address=self.host,
            vendor="Arista",
            device_type="Switch",
            os_version=os_version,
            is_live=True,
            credential_status="authenticated",
            interfaces=interfaces,
            management_services=mgmt,
            firewall_rules=[],
            raw_configuration=raw_config,
        )
