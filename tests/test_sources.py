import os
import tempfile
import unittest

from datapce_scan import sources
from tests.helpers import make_fixture


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = make_fixture(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_reads_tool_calls_and_dedupes(self):
        res = sources.read_claude_code(self.root)
        ids = [c.tool_use_id for c in res.calls]
        self.assertEqual(sorted(ids), sorted(["t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9"]))
        self.assertEqual(res.files, 3)
        self.assertEqual(res.bad_lines, 1)
        self.assertEqual(res.duplicates, 1)

    def test_fields(self):
        res = sources.read_claude_code(self.root)
        c = [c for c in res.calls if c.tool_use_id == "t2"][0]
        self.assertEqual(c.tool, "Bash")
        self.assertEqual(c.command, "cd /tmp/w && rm -rf /tmp/w/build")
        self.assertEqual(c.cwd, "/Users/someone/src/alpha")
        self.assertEqual(c.session, "s1")
        self.assertEqual(c.ts, "2026-10-20T09:01:00Z")
        r = [c for c in res.calls if c.tool_use_id == "t3"][0]
        self.assertIsNone(r.command)

    def test_subagents_optional(self):
        res = sources.read_claude_code(self.root, include_subagents=True)
        self.assertIn("t10", [c.tool_use_id for c in res.calls])
        self.assertEqual(res.files, 4)

    def test_date_filter(self):
        res = sources.read_claude_code(self.root, since="2026-10-21")
        self.assertEqual({c.session for c in res.calls}, {"s2", "s3"})
        res = sources.read_claude_code(self.root, until="2026-10-20")
        self.assertEqual({c.session for c in res.calls}, {"s1"})

    def test_missing_root(self):
        res = sources.read_claude_code(os.path.join(self.tmp.name, "nope"))
        self.assertEqual((res.files, len(res.calls)), (0, 0))

    def test_never_opens_for_write(self):
        before = {p: os.path.getmtime(os.path.join(dp, p)) for dp, _, fs in os.walk(self.root)
                  for p in fs}
        sources.read_claude_code(self.root, include_subagents=True)
        after = {p: os.path.getmtime(os.path.join(dp, p)) for dp, _, fs in os.walk(self.root)
                 for p in fs}
        self.assertEqual(before, after)

    def test_skips_dangling_links_and_dirs(self):
        base = {subs: sources.read_claude_code(self.root, include_subagents=subs) for subs in (False, True)}
        proj = os.path.join(self.root, "-odd")
        os.makedirs(os.path.join(proj, "x.jsonl"))  # a directory with a .jsonl name
        os.symlink(os.path.join(self.tmp.name, "gone.jsonl"), os.path.join(proj, "dangling.jsonl"))
        sub = os.path.join(proj, "s1", "subagents")
        os.makedirs(os.path.join(sub, "y.jsonl"))
        os.symlink(os.path.join(self.tmp.name, "gone2.jsonl"), os.path.join(sub, "dangling.jsonl"))
        for subs in (False, True):
            res = sources.read_claude_code(self.root, include_subagents=subs)
            self.assertEqual((res.files, len(res.calls), res.bad_lines),
                             (base[subs].files, len(base[subs].calls), base[subs].bad_lines))

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads mode-000 files")
    def test_unreadable_file_is_skipped(self):
        base = sources.read_claude_code(self.root)
        locked = os.path.join(self.root, "-odd", "locked.jsonl")
        os.makedirs(os.path.dirname(locked))
        with open(locked, "w") as fh:
            fh.write("{}\n")
        os.chmod(locked, 0)
        try:
            res = sources.read_claude_code(self.root)
        finally:
            os.chmod(locked, 0o600)
        self.assertEqual(len(res.calls), len(base.calls))


if __name__ == "__main__":
    unittest.main()
