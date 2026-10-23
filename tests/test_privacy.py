import unittest

from datapce_scan import privacy as P


class PrivacyTests(unittest.TestCase):
    def test_safe_label(self):
        self.assertEqual(P.safe_label("git"), "git")
        self.assertEqual(P.safe_label("a@b.example"), "(redacted)")
        self.assertEqual(P.safe_label("ghp_abcdefghijklmnopqrstuvwxyz0123"), "(redacted)")
        self.assertEqual(P.safe_label("/Users/x/bin/tool"), "tool")
        self.assertLessEqual(len(P.safe_label("x" * 100)), 40)

    def test_redact_text(self):
        t = P.redact("curl -H 'Authorization: Bearer abc.def-ghi' -u me@corp.example sk-ant-1234567890abcdefXYZ")
        self.assertNotIn("me@corp.example", t)
        self.assertNotIn("abc.def-ghi", t)
        self.assertNotIn("sk-ant-1234567890abcdefXYZ", t)
        t = P.redact("export API_TOKEN=supersecretvalue123; PASSWORD='x y'")
        self.assertNotIn("supersecretvalue123", t)
        self.assertNotIn("x y", t)

    def test_check_output(self):
        P.check_output("calls 12", home="/Users/x")
        with self.assertRaises(P.PrivacyError):
            P.check_output("see a@b.example", home="/Users/x")
        with self.assertRaises(P.PrivacyError):
            P.check_output("path /Users/x/src", home="/Users/x")


if __name__ == "__main__":
    unittest.main()
