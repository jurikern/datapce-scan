import json
import tempfile
import unittest

from datapce_scan import report, rules, sources
from tests.helpers import make_fixture


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.res = sources.read_claude_code(make_fixture(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()


class SummaryTests(Base):
    def test_counts(self):
        s = report.summarize(self.res, home="/Users/someone")
        self.assertEqual(s["totals"]["tool_calls"], 9)
        self.assertEqual(s["totals"]["bash_calls"], 7)
        self.assertEqual(s["totals"]["sessions"], 3)
        self.assertEqual(s["totals"]["active_hours"], 3)  # 10-20 09h, 10-20 10h, 10-21 22h
        self.assertEqual(s["totals"]["files"], 3)
        self.assertEqual(dict(s["tools"]), {"Bash": 7, "Read": 1, "Edit": 1})
        fam = dict(s["families"])
        self.assertEqual(fam["git"], 3)
        self.assertEqual(fam["rm"], 2)
        self.assertEqual(fam["bash"], 1)
        self.assertEqual(dict(s["repos"]), {"alpha": 5, "beta": 4})
        self.assertEqual(dict(s["days"]), {"2026-10-20": 5, "2026-10-21": 4})

    def test_hashed_repos(self):
        s = report.summarize(self.res, home="/Users/someone", hash_repos=True)
        keys = [k for k, _ in s["repos"]]
        self.assertTrue(all(k.startswith("r-") and len(k) == 10 for k in keys), keys)

    def test_repo_label_rules(self):
        h = "/Users/someone"
        self.assertEqual(report.repo_label("/Users/someone/src/x/.claude/worktrees/w1", h), "x")
        self.assertEqual(report.repo_label("/private/tmp/abc", h), "(temp dir)")
        self.assertEqual(report.repo_label("/Users/someone", h), "(home)")
        self.assertEqual(report.repo_label(None, h), "(unknown)")

    def test_top_n_groups_rest(self):
        s = report.summarize(self.res, home="/Users/someone", top=1)
        self.assertEqual(len(s["tools"]), 2)
        self.assertTrue(s["tools"][-1][0].startswith("(other"))


class ReplayTests(Base):
    def test_datapce6(self):
        r = report.replay(self.res, rules.load("datapce-6"), home="/Users/someone")
        self.assertEqual(r["bash_calls"], 7)
        self.assertEqual(r["denies"], 2)
        self.assertEqual(dict(r["denies_by_rule"]), {"rm-rf-root": 1, "git-push-force": 1})
        self.assertEqual(r["temp_target_denies"], 0)
        self.assertEqual(r["bash_hours"], 3)
        self.assertAlmostEqual(r["denies_per_bash_hour"], 0.667, places=3)

    def test_v0_temp_share(self):
        r = report.replay(self.res, rules.load("datapce-6-v0"), home="/Users/someone")
        self.assertEqual(dict(r["denies_by_rule"]), {"rm-rf-root": 1, "git-push-force": 1})
        self.assertEqual(r["temp_target_denies"], 1)   # rm -rf /tmp/w/build
        self.assertAlmostEqual(r["temp_target_share"], 0.5)

    def test_replay_many_matches_single(self):
        sets = [rules.load(n) for n in ("datapce-6", "datapce-6-v0", "sage")]
        many = report.replay_many(self.res, sets, home="/Users/someone")
        for s, m in zip(sets, many):
            one = report.replay(self.res, s, home="/Users/someone")
            self.assertEqual(one, m)

    def test_heredoc_only_counted(self):
        r = report.replay(self.res, rules.load("sage"), home="/Users/someone")
        self.assertIn("heredoc_only_denies", r)

    def test_meta_carried(self):
        r = report.replay(self.res, rules.load("sage"), home="/Users/someone")
        for k in ("source_url", "licence", "fetched", "attribution"):
            self.assertTrue(r["ruleset"][k], k)


class RenderTests(Base):
    def outputs(self):
        s = report.summarize(self.res, home="/Users/someone")
        r = [report.replay(self.res, rules.load(n), home="/Users/someone") for n in rules.available()]
        return [report.render_summary(s, "table"), report.render_summary(s, "tsv"),
                report.render_summary(s, "json"), report.render_replay(r, "table"),
                report.render_replay(r, "tsv"), report.render_replay(r, "json")]

    def test_privacy_line_first(self):
        for out in self.outputs():
            if out.lstrip().startswith("{"):
                self.assertIn("privacy", json.loads(out))
            else:
                self.assertIn(report.PRIVACY_LINE, out.splitlines()[0])

    def test_no_command_text_email_or_secret(self):
        for out in self.outputs():
            for bad in ("someone@example.com", "sk-live", "Bearer", "api.example.com",
                        "/Users/someone", "rm -rf", "git push --force", "/tmp/w"):
                self.assertNotIn(bad, out)

    def test_json_parses(self):
        outs = self.outputs()
        self.assertEqual(json.loads(outs[2])["totals"]["bash_calls"], 7)
        self.assertTrue(json.loads(outs[5])["rulesets"])

    def test_tsv_shape(self):
        for out in (self.outputs()[1], self.outputs()[4]):
            rows = [ln for ln in out.splitlines() if not ln.startswith("#")]
            self.assertTrue(rows)
            widths = {len(r.split("\t")) for r in rows}
            self.assertEqual(len(widths), 1, widths)


if __name__ == "__main__":
    unittest.main()


class BashCountRuleTests(unittest.TestCase):
    """Defect 2: a Bash tool call without a command string made Totals and Tools differ."""

    def test_totals_and_tools_agree(self):
        from tests.helpers import assistant_line, write_project
        with tempfile.TemporaryDirectory() as d:
            make_fixture(d)
            write_project(d, "-Users-someone-src-gamma", "s9", [
                assistant_line("2026-10-21T23:00:00Z", "s9", "/Users/someone/src/gamma", [
                    ("t90", "Bash", {"description": "no command field", "input": "x"}),
                ])])
            res = sources.read_claude_code(d)
            s = report.summarize(res, home="/Users/someone")
            self.assertEqual(s["totals"]["bash_calls"], dict(s["tools"])["Bash"])
            self.assertEqual(s["totals"]["bash_calls_without_command"], 1)
            r = report.replay(res, rules.load("datapce-6"), home="/Users/someone")
            self.assertEqual(r["bash_calls"], s["totals"]["bash_calls"])
            self.assertEqual(r["bash_calls_without_command"], 1)


class FamilyAllowListTests(Base):
    """Defect 3: a private script name must not show as a family by default."""

    def _res(self, d):
        from tests.helpers import assistant_line, bash, write_project
        make_fixture(d)
        write_project(d, "-Users-someone-src-gamma", "s8", [
            assistant_line("2026-10-21T23:00:00Z", "s8", "/Users/someone/src/gamma", [
                bash("t80", "./deploy-acme-internal.sh --now"),
                bash("t81", "/Users/someone/bin/zz-private-tool x && python3.14 -V"),
            ])])
        return sources.read_claude_code(d)

    def test_default_hides_non_public_families(self):
        with tempfile.TemporaryDirectory() as d:
            s = report.summarize(self._res(d), home="/Users/someone", top=50)
            fam = dict(s["families"])
            self.assertNotIn("deploy-acme-internal.sh", fam)
            self.assertNotIn("zz-private-tool", fam)
            self.assertIn("git", fam)
            self.assertIn("python3.14", fam)
            other = [k for k in fam if k.startswith("(other")]
            self.assertEqual(len(other), 1)
            self.assertEqual(fam[other[0]], 2)
            for fmt in ("table", "tsv", "json"):
                out = report.render_summary(s, fmt)
                self.assertNotIn("deploy-acme", out)
                self.assertNotIn("WARNING", out)

    def test_show_local_families_with_warning(self):
        with tempfile.TemporaryDirectory() as d:
            s = report.summarize(self._res(d), home="/Users/someone", top=50, local_families=True)
            self.assertIn("deploy-acme-internal.sh", dict(s["families"]))
            for fmt in ("table", "tsv", "json"):
                out = report.render_summary(s, fmt)
                self.assertIn("WARNING", out)
                self.assertLess(out.index("WARNING"), out.index("deploy-acme-internal.sh"))
