import io
import json
import os
import socket
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from datapce_scan import cli, report
from tests.helpers import make_fixture


def run(argv, tty=False):
    out, err = io.StringIO(), io.StringIO()
    out.isatty = lambda: tty  # type: ignore[attr-defined]
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = make_fixture(self.tmp.name)
        self.base = ["--projects", self.root]
        self.env = mock.patch.dict(os.environ, {"HOME": "/Users/someone"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_default_is_summary_table(self):
        code, out, _ = run(self.base)
        self.assertEqual(code, 0)
        self.assertIn(report.PRIVACY_LINE, out.splitlines()[0])
        self.assertIn("Bash", out)

    def test_summary_json_and_tsv(self):
        _, out, _ = run(self.base + ["--json"])
        self.assertEqual(json.loads(out)["totals"]["bash_calls"], 7)
        _, out, _ = run(self.base + ["--tsv"])
        self.assertIn("totals\tbash_calls\t7", out)

    def test_replay_one_and_all(self):
        code, out, _ = run(["replay", "--rules", "datapce-6"] + self.base + ["--json"])
        self.assertEqual(code, 0)
        d = json.loads(out)
        self.assertEqual(d["rulesets"][0]["denies"], 2)
        _, out, _ = run(["replay", "--rules", "all"] + self.base + ["--json"])
        self.assertGreaterEqual(len(json.loads(out)["rulesets"]), 5)
        _, out, _ = run(["replay", "--rules", "datapce-6,sage"] + self.base)
        self.assertIn("datapce-6", out)
        self.assertIn("sage", out)

    def test_unknown_ruleset(self):
        code, _, err = run(["replay", "--rules", "nope"] + self.base)
        self.assertEqual(code, 2)
        self.assertIn("nope", err)

    def test_rules_list(self):
        code, out, _ = run(["rules"])
        self.assertEqual(code, 0)
        self.assertIn("cc-safety-net", out)
        self.assertIn("MIT", out)

    def test_show_examples_off_by_default(self):
        _, out, _ = run(["replay", "--rules", "datapce-6"] + self.base, tty=True)
        self.assertNotIn("git push", out)

    def test_show_examples_needs_terminal_and_warns(self):
        code, out, err = run(["replay", "--rules", "datapce-6", "--show-examples"] + self.base)
        self.assertEqual(code, 2)
        self.assertNotIn("git push", out)
        code, out, _ = run(["replay", "--rules", "datapce-6", "--show-examples"] + self.base, tty=True)
        self.assertEqual(code, 0)
        self.assertIn("WARNING", out)
        self.assertIn("rm -fr /", out)
        self.assertLess(out.index("WARNING"), out.index("rm -fr /"))

    def test_show_examples_redacts_email_and_secrets(self):
        _, out, _ = run(["replay", "--rules", "sage", "--show-examples"] + self.base, tty=True)
        self.assertNotIn("sk-live-ABCDEFGH1234567890abcd", out)
        self.assertNotIn("someone@example.com", out)

    def test_show_examples_not_with_json(self):
        code, _, _ = run(["replay", "--rules", "datapce-6", "--show-examples", "--json"] + self.base,
                         tty=True)
        self.assertEqual(code, 2)

    def test_no_network(self):
        def boom(*a, **k):
            raise AssertionError("network call")
        with mock.patch.object(socket, "socket", boom), \
                mock.patch.object(socket, "create_connection", boom):
            self.assertEqual(run(self.base)[0], 0)
            self.assertEqual(run(["replay", "--rules", "all"] + self.base)[0], 0)

    def test_empty_projects(self):
        code, out, _ = run(["--projects", os.path.join(self.tmp.name, "none")])
        self.assertEqual(code, 0)
        self.assertIn("0", out)


if __name__ == "__main__":
    unittest.main()


class LocalFamiliesFlagTests(unittest.TestCase):
    def test_flag_parses_and_warns(self):
        with tempfile.TemporaryDirectory() as d:
            make_fixture(d)
            with mock.patch.dict(os.environ, {"HOME": "/Users/someone"}):
                code, out, _ = run(["--projects", d, "--show-local-families"])
                self.assertEqual(code, 0)
                self.assertIn("WARNING", out)
                code, out, _ = run(["--projects", d])
                self.assertNotIn("WARNING", out)
