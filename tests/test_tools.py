"""Unit tests for the analysis tools (run on the synthetic sample data)."""
import hashlib
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
SAMPLE = os.path.join(ROOT, "data", "sample")

import audit_sudo  # noqa: E402
import decode_commands  # noqa: E402
import hash_check  # noqa: E402
import http_downloads  # noqa: E402
import ps_check  # noqa: E402
import scan_iocs  # noqa: E402
import ssh_failures  # noqa: E402
from zeek_utils import is_true, read_zeek  # noqa: E402


def sample(name):
    return os.path.join(SAMPLE, name)


def read(name):
    with open(sample(name), encoding="utf-8") as handle:
        return handle.read()


class SshTests(unittest.TestCase):
    def test_counts_match_lab(self):
        r = ssh_failures.summarize(read_zeek(sample("ssh.log")))
        self.assertEqual(r["total_attempts"], 54)
        self.assertEqual(r["failed"], 52)
        self.assertEqual(r["successful"], 2)
        self.assertEqual(r["top_sources"][0][0], "23.20.23.147")

    def test_json_lines_input(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write('{"id": {"orig_h": "1.1.1.1"}, "auth_success": true}\n')
            fh.write('{"id": {"orig_h": "1.1.1.1"}, "auth_success": null}\n')
        r = ssh_failures.summarize(read_zeek(fh.name))
        os.unlink(fh.name)
        self.assertEqual((r["total_attempts"], r["failed"], r["successful"]), (2, 1, 1))

    def test_is_true(self):
        self.assertTrue(is_true("T"))
        self.assertTrue(is_true(True))
        self.assertFalse(is_true(None))
        self.assertFalse(is_true("-"))


class HttpTests(unittest.TestCase):
    def test_downloads_and_tool(self):
        s = http_downloads.summarize(list(read_zeek(sample("http.log"))))
        self.assertTrue(s["wget_seen"])
        self.assertEqual(len(s["stage1"]), 3)
        self.assertEqual(s["remote_count"], 9)
        self.assertEqual(s["get_requests"], 12)
        self.assertIn(("174.129.57.253", 2), s["remote_by_host"])


class SudoTests(unittest.TestCase):
    def test_intersection_is_manager_and_sean(self):
        cracked = audit_sudo.parse_john(read("john_output.txt"))
        sudo = audit_sudo.parse_sudoers(read("sudoers.log"))
        self.assertEqual(set(cracked), {"manager", "gibson", "sean"})
        self.assertEqual(audit_sudo.audit(cracked, sudo), ["manager", "sean"])

    def test_john_show_format(self):
        cracked = audit_sudo.parse_john("manager:forgot:1000:1000::/home/manager:/bin/bash\n")
        self.assertEqual(cracked, {"manager": "forgot"})

    def test_sudoers_ignores_comments_and_groups(self):
        users = audit_sudo.parse_sudoers("# x\n%admin ALL=(ALL) ALL\nDefaults env_reset\nbob ALL=(ALL) ALL\n")
        self.assertEqual(users, {"bob"})


class PsTests(unittest.TestCase):
    def test_path_missing(self):
        self.assertEqual(ps_check.find_lines(read("ps.log"), "/var/mail/mail"), [])

    def test_path_found(self):
        hits = ps_check.find_lines("a\n/var/mail/mail &\n", "/var/mail/mail")
        self.assertEqual(hits[0][0], 2)


class DecodeTests(unittest.TestCase):
    def test_lab_constants(self):
        names = [decode_commands.command_name(decode_commands.decode_constant(c))
                 for c in decode_commands.LAB_CONSTANTS]
        self.assertEqual(names, ["NOP", "RUN"])
        self.assertEqual(",".join(sorted(names)), "NOP,RUN")


class HashTests(unittest.TestCase):
    def test_known_digest(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"hello")
        h = hash_check.file_hashes(fh.name)
        os.unlink(fh.name)
        self.assertEqual(h["md5"], hashlib.md5(b"hello").hexdigest())
        self.assertEqual(h["sha256"], hashlib.sha256(b"hello").hexdigest())


class IocTests(unittest.TestCase):
    def test_finds_ip_in_sample_http_log(self):
        iocs = scan_iocs.load_iocs(os.path.join(ROOT, "data", "iocs.json"))
        hits = scan_iocs.scan_file(sample("http.log"), iocs)
        self.assertTrue(any(v == "174.129.57.253" for _, _, v in hits))


if __name__ == "__main__":
    unittest.main()
