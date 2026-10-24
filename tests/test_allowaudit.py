"""P2-B acceptance: allow-audit replays standing allow rules over past calls, flags broad rules
and rules that matched destructive commands. Synthetic transcripts and settings only."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from datapce_scan import allowaudit, cli, rules, sources
from tests.helpers import assistant_line, bash, make_fixture, write_project

SECRET = "sk-live-XXXXXXXX1234567890abcdef"
ALLOW = [
    "Bash(git status:*)", "Bash(rm:*)", "Bash(*)", "Bash(git *)", "Bash(python3 *)", "Read",
    "Bash(npm test)", "Bash(cd /tmp/w && rm -rf /tmp/w/build)",
    "Bash(curl -H 'Authorization: Bearer %s' https://api.example.com)" % SECRET,
    "WebFetch(domain:example.com)", "mcp__github__*", "Bash(grep *)",
]


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    out.isatty = lambda: False  # type: ignore[attr-defined]
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class TargetTests(unittest.TestCase):
    def test_target_of_file_and_fetch_calls(self):
        with tempfile.TemporaryDirectory() as d:
            res = sources.read_claude_code(make_fixture(d))
            by = {c.tool_use_id: c for c in res.calls}
            self.assertEqual(by["t3"].target, "/Users/someone/src/alpha/a.py")
            self.assertEqual(by["t8"].target, "x")
            self.assertIsNone(by["t1"].target)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = make_fixture(os.path.join(self.tmp.name, "projects"))
        write_project(self.root, "-Users-someone-src-alpha", "s9", [
            assistant_line("2026-10-21T09:00:00Z", "s9", "/Users/someone/src/alpha",
                           [bash("g1", "grep -rn 'rm -rf /' docs")])])
        self.settings = os.path.join(self.tmp.name, "my-settings.json")
        with open(self.settings, "w") as f:
            json.dump({"permissions": {"allow": ALLOW, "deny": ["Bash(sudo *)"]}}, f)
        self.env = mock.patch.dict(os.environ, {"HOME": "/Users/someone"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def audit(self):
        res = sources.read_claude_code(self.root)
        files = allowaudit.load_settings([("file 1", self.settings)])
        guards = [rules.load(n) for n in rules.available()]
        return allowaudit.audit(res, files, guards, "/Users/someone")

    def by_rule(self, a):
        return {r["rule_raw"]: r for r in a["_rules_private"]}

    def test_matches_per_rule(self):
        r = self.by_rule(self.audit())
        self.assertEqual(r["Bash(git status:*)"]["calls"], 1)
        self.assertEqual(r["Bash(rm:*)"]["calls"], 2)
        self.assertEqual(r["Bash(*)"]["calls"], 8)
        self.assertEqual(r["Bash(grep *)"]["calls"], 1)
        self.assertEqual(r["Bash(git *)"]["calls"], 3)
        self.assertEqual(r["Read"]["calls"], 1)
        self.assertEqual(r["Bash(npm test)"]["calls"], 1)
        self.assertEqual(r["Bash(python3 *)"]["calls"], 0)

    def test_flags(self):
        r = self.by_rule(self.audit())
        self.assertIn(allowaudit.F_ALL, r["Bash(*)"]["flags"])
        self.assertIn(allowaudit.F_ANYSUB, r["Bash(git *)"]["flags"])
        self.assertIn(allowaudit.F_DESTRUCTIVE, r["Bash(rm:*)"]["flags"])
        self.assertIn(allowaudit.F_DROPPED, r["Bash(python3 *)"]["flags"])
        self.assertIn(allowaudit.F_UNUSED, r["Bash(python3 *)"]["flags"])
        self.assertIn(allowaudit.F_TOOL, r["Read"]["flags"])
        self.assertIn(allowaudit.F_ONEOFF, r["Bash(cd /tmp/w && rm -rf /tmp/w/build)"]["flags"])
        self.assertEqual(r["Bash(git status:*)"]["flags"], [])
        self.assertEqual(r["Bash(npm test)"]["flags"], [])

    def test_destructive_matches(self):
        r = self.by_rule(self.audit())
        # rm -fr / is a real deny; rm -rf /tmp/w/build has a temp-dir target: likely false
        self.assertEqual(r["Bash(rm:*)"]["destructive"], 1)
        self.assertEqual(r["Bash(rm:*)"]["likely_false"], 1)
        # grep is read-only: a text rule that matches its pattern argument is likely false
        self.assertEqual(r["Bash(grep *)"]["destructive"], 0)
        self.assertEqual(r["Bash(grep *)"]["likely_false"], 1)
        self.assertGreaterEqual(r["Bash(*)"]["destructive"], 3)
        self.assertEqual(r["Bash(git *)"]["destructive"], 1)  # git push --force
        self.assertEqual(r["Bash(git status:*)"]["destructive"], 0)
        self.assertTrue(any("git.push-force" in g for g in r["Bash(git *)"]["guard_rules"]))

    def test_totals(self):
        t = self.audit()["totals"]
        self.assertEqual(t["allow_rules"], len(ALLOW))
        self.assertEqual(t["deny_rules"], 1)
        self.assertEqual(t["with_likely_false_only"], 1)  # Bash(grep *)
        self.assertEqual(t["with_destructive_matches"], 3)
        self.assertGreaterEqual(t["flagged"], 7)
        self.assertEqual(t["unused"], 5)

    def test_cli_hides_long_rules_secrets_and_paths(self):
        code, out, err = run(["allow-audit", "--projects", self.root, "--settings", self.settings])
        self.assertEqual(code, 0, err)
        self.assertIn("Bash(rm:*)", out)
        self.assertIn("Bash(git status:*)", out)
        self.assertIn("Nothing was written", out)
        self.assertIn("file 1", out)
        for leak in (SECRET, "api.example.com", "my-settings", self.tmp.name, "/tmp/w"):
            self.assertNotIn(leak, out)
        self.assertIn("(text hidden", out)
        self.assertIn("mcp__github__*", out)

    def test_cli_json(self):
        code, out, _ = run(["allow-audit", "--projects", self.root, "--settings", self.settings,
                            "--json"])
        self.assertEqual(code, 0)
        d = json.loads(out)
        self.assertNotIn("_rules_private", d)
        self.assertNotIn(SECRET, out)
        self.assertEqual(d["totals"]["allow_rules"], len(ALLOW))

    def test_writes_no_file(self):
        before = sorted(os.walk(self.tmp.name))
        mtime = os.path.getmtime(self.settings)
        run(["allow-audit", "--projects", self.root, "--settings", self.settings])
        self.assertEqual(before, sorted(os.walk(self.tmp.name)))
        self.assertEqual(mtime, os.path.getmtime(self.settings))


class DefaultLocationTests(unittest.TestCase):
    def test_user_and_project_local_found(self):
        with tempfile.TemporaryDirectory() as d:
            home, proj = os.path.join(d, "home"), os.path.join(d, "proj")
            for p in (os.path.join(home, ".claude"), os.path.join(proj, ".claude")):
                os.makedirs(p)
            with open(os.path.join(home, ".claude", "settings.json"), "w") as f:
                json.dump({"permissions": {"allow": ["Bash(npm test)"]}}, f)
            with open(os.path.join(proj, ".claude", "settings.local.json"), "w") as f:
                json.dump({"permissions": {"allow": ["Bash(git status:*)"]}}, f)
            root = os.path.join(d, "projects")
            write_project(root, "-proj", "s1", [
                assistant_line("2026-10-20T09:00:00Z", "s1", proj, [bash("x1", "npm test")])])
            res = sources.read_claude_code(root)
            found = allowaudit.default_settings(res, home, managed=())
            scopes = sorted(s for s, _ in found)
            self.assertEqual(scopes[0], "project-local")
            self.assertIn("user", scopes)


if __name__ == "__main__":
    unittest.main()


class SecretRuleTextTests(unittest.TestCase):
    """Review finding 1: rule text that holds a secret must never print (table, JSON, TSV)."""
    KEY = "sk-ant-api03-" + "AbCdEfGhIjKlMnOpQrSt"
    PW = "Hunter2" + "Secret99xyz"
    RULES = ["Bash(curl -H x-api-key:%s)" % KEY, "Bash(mysql -u root -p%s)" % PW,
             "Bash(mysql -u root -p %s)" % PW, "mcp__srv__%s" % KEY.replace("-", "_"),
             "Bash(git status:*)"]

    def test_display_hides_secret_shaped_rules(self):
        for rule in self.RULES[:4]:
            shown = allowaudit.display(rule)
            self.assertNotIn(self.KEY, shown)
            self.assertNotIn(self.PW, shown)
            self.assertNotIn(self.KEY.replace("-", "_"), shown)
            # round-2 ruling (fix A): no hash of rule text; the hidden marker shows instead
            self.assertIn("(text hidden", shown)
            self.assertNotRegex(shown, r"#[0-9a-f]{6,}")
        self.assertEqual(allowaudit.display("Bash(git status:*)"), "Bash(git status:*)")
        self.assertEqual(allowaudit.display("Bash(npm test)"), "Bash(npm test)")
        self.assertEqual(allowaudit.display("Bash(python3:*)"), "Bash(python3:*)")
        self.assertEqual(allowaudit.display("Bash(sha256sum *)"), "Bash(sha256sum *)")

    def test_cli_all_formats_hide_secret_rules(self):
        with tempfile.TemporaryDirectory() as d:
            root = make_fixture(os.path.join(d, "projects"))
            settings = os.path.join(d, "s.json")
            with open(settings, "w") as f:
                json.dump({"permissions": {"allow": self.RULES}}, f)
            with mock.patch.dict(os.environ, {"HOME": "/Users/someone"}):
                for extra in ([], ["--json"], ["--tsv"]):
                    code, out, err = run(["allow-audit", "--projects", root, "--settings",
                                          settings] + extra)
                    self.assertEqual(code, 0, err)
                    for leak in (self.KEY, self.PW, "AbCdEfGhIjKlMnOpQrSt"):
                        self.assertNotIn(leak, out, extra)
                    self.assertIn("Bash(git status:*)", out)


class SettingsShapeTests(unittest.TestCase):
    """Review finding 10: a string value for allow, deny or ask must not split into characters."""

    def test_string_values_are_not_lists(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.json")
            with open(p, "w") as f:
                json.dump({"permissions": {"allow": "Bash(rm:*)", "deny": "Bash(x)",
                                           "ask": ["Bash(y)"]}}, f)
            e = allowaudit.load_settings([("file 1", p)])[0]
            self.assertEqual(e["allow"], [])
            self.assertEqual(e["deny"], 0)
            self.assertEqual(e["ask"], 1)
            self.assertEqual(e["error"], "not a list: allow, deny")


class DocsMatchingAuditTests(unittest.TestCase):
    """Review finding 4 in allow-audit: anchors per settings source, assignments, find."""

    def test_replay_follows_docs(self):
        with tempfile.TemporaryDirectory() as d:
            cwd = "/Users/someone/src/alpha"
            root = os.path.join(d, "projects")
            write_project(root, "-Users-someone-src-alpha", "s1", [
                assistant_line("2026-10-20T09:00:00Z", "s1", cwd, [
                    ("e1", "Write", {"file_path": cwd + "/src/a.py", "content": "x"}),
                    bash("b1", "FOO=1 npm test"), bash("b2", "find . -delete"),
                    bash("b3", "git 'push' origin main")])])
            settings = os.path.join(d, "s.json")
            with open(settings, "w") as f:
                json.dump({"permissions": {"allow": [
                    "Edit(/src/**)", "Edit(./src/**)", "Write(./src/**)", "Bash(npm test)",
                    "Bash(find *)", "Bash(git push *)", "mcp__*"]}}, f)
            res = sources.read_claude_code(root)
            files = allowaudit.load_settings([("file 1", settings)])
            a = allowaudit.audit(res, files, [], "/Users/someone")
            calls = {r["rule_raw"]: r["calls"] for r in a["_rules_private"]}
            self.assertEqual(calls["Edit(/src/**)"], 0)  # anchors at the settings file's dir
            self.assertEqual(calls["Edit(./src/**)"], 1)  # Edit rules cover Write
            self.assertEqual(calls["Write(./src/**)"], 0)  # never matches
            self.assertEqual(calls["Bash(npm test)"], 0)  # FOO= is not a known-safe variable
            self.assertEqual(calls["Bash(find *)"], 0)  # prefix rule cannot approve -delete
            self.assertEqual(calls["Bash(git push *)"], 0)  # 'push' quoted, as written
            flags = {r["rule_raw"]: r["flags"] for r in a["_rules_private"]}
            self.assertIn(allowaudit.F_SKIPPED, flags["mcp__*"])
            self.assertIn(allowaudit.F_SKIPPED, flags["Write(./src/**)"])


class DocsNotesTests(unittest.TestCase):
    """Review finding 9: auto mode also drops PowerShell(*) and Monitor allow rules."""

    def test_flags_and_notes(self):
        self.assertIn(allowaudit.F_DROPPED, allowaudit.flags_for("PowerShell"))
        self.assertIn(allowaudit.F_DROPPED, allowaudit.flags_for("PowerShell(*)"))
        self.assertIn(allowaudit.F_DROPPED, allowaudit.flags_for("Monitor"))
        with tempfile.TemporaryDirectory() as d:
            root = make_fixture(os.path.join(d, "projects"))
            settings = os.path.join(d, "s.json")
            with open(settings, "w") as f:
                json.dump({"permissions": {"allow": ["Read"]}}, f)
            code, out, _ = run(["allow-audit", "--projects", root, "--settings", settings])
            self.assertIn("PowerShell(*)", out)
            self.assertIn("Monitor", out)
            code, out, _ = run(["allow-suggest", "--projects", root])
            self.assertIn("PowerShell(*)", out)
            self.assertIn("Monitor", out)


class PublicShapeDisplayTests(unittest.TestCase):
    """Fix round 2, item A: a rule prints only the program, a listed subcommand, flag-shaped
    words and `*`. Every other word is hidden. No hash and no length of the rule text."""
    BREAKERS = ["Bash(redis-cli -a hunterpass ping)", "Bash(zip -P hunterpass *)",
                "Bash(openssl enc -k mypassphrase *)", "Bash(ssh-keygen -N mypassphrase *)",
                "Bash(psql --client-secret topsecretval *)",
                "Bash(npm config set authtoken lowercasesecret *)",
                "Bash(mysql -u root -pxy *)", "Bash(git hunterpass *)",
                "mcp__acme-internal__query"]
    WORDS = ("hunterpass", "mypassphrase", "topsecretval", "authtoken", "lowercasesecret",
             "-pxy", "acme-internal", "root")

    def test_display_shows_public_shape_only(self):
        for k, rule in enumerate(self.BREAKERS):
            shown = allowaudit.display(rule, k + 1)
            for w in self.WORDS:
                self.assertNotIn(w, shown, rule)
            self.assertNotRegex(shown, r"#[0-9a-f]{6,}", rule)
            self.assertNotIn("chars", shown, rule)
            self.assertIn("rule %d" % (k + 1), shown, rule)
        self.assertTrue(allowaudit.display(self.BREAKERS[0], 1).startswith("Bash(redis-cli -a "))
        # --client-secret is not on a public long-flag list: it is hidden too
        self.assertTrue(allowaudit.display(self.BREAKERS[4], 5).startswith(
            "Bash(psql <w> <w> *)"))
        self.assertTrue(allowaudit.display(self.BREAKERS[5], 6).startswith("Bash(npm config "))
        self.assertEqual(allowaudit.display("Bash(git status:*)", 9), "Bash(git status:*)")
        self.assertEqual(allowaudit.display("mcp__github__*", 9), "mcp__github__*")

    def test_no_word_outside_the_public_shapes(self):
        for rule in ("Bash(node12345678 x)", "Bash(git --token=abc *)", "Bash(ls -labc)",
                     "Bash(gh pr list -R otherhost/o/r)", "Read(~/private-dir/**)",
                     "Hunterpasstool", "mcp__github__hunterpass"):
            shown = allowaudit.display(rule, 1)
            for w in ("12345678", "abc", "otherhost", "private-dir", "Hunterpasstool",
                      "hunterpass"):
                self.assertNotIn(w, shown, rule)

    def test_cli_all_formats_hide_breaker_words(self):
        with tempfile.TemporaryDirectory() as d:
            root = make_fixture(os.path.join(d, "projects"))
            settings = os.path.join(d, "s.json")
            with open(settings, "w") as f:
                json.dump({"permissions": {"allow": self.BREAKERS + ["Bash(git status:*)"]}}, f)
            with mock.patch.dict(os.environ, {"HOME": "/Users/someone"}):
                for extra in ([], ["--json"], ["--tsv"]):
                    code, out, err = run(["allow-audit", "--projects", root, "--settings",
                                          settings] + extra)
                    self.assertEqual(code, 0, err)
                    for w in self.WORDS:
                        self.assertNotIn(w, out, extra)
                    self.assertNotRegex(out, r"#[0-9a-f]{8}")
                    self.assertIn("Bash(git status:*)", out)


class LongFlagAllowListTests(unittest.TestCase):
    """A long flag prints only if it is on the public list for its program (or the short
    common list). Any other long flag can be a private word and shows as <w>."""

    def test_private_long_flag_is_hidden(self):
        for rule in ("Bash(./deploy --acmecorp-prod)", "Bash(git log --acmecorp-prod)",
                     "Bash(git push --acmecorp-prod *)", "Bash(mytool --acmecorp-prod)",
                     "Bash(ls --acmecorp-prod)"):
            shown = allowaudit.display(rule, 1)
            self.assertNotIn("acmecorp", shown, rule)
            self.assertIn("<w>", shown, rule)

    def test_public_long_flags_still_print(self):
        self.assertEqual(allowaudit.display("Bash(git log --oneline *)", 1),
                         "Bash(git log --oneline *)")
        self.assertEqual(allowaudit.display("Bash(git branch --show-current)", 1),
                         "Bash(git branch --show-current)")
        self.assertEqual(allowaudit.display("Bash(ls --help)", 1), "Bash(ls --help)")
        self.assertEqual(allowaudit.display("Bash(gh pr list --json *)", 1),
                         "Bash(gh pr list --json *)")
        # a flag on another program's list does not print here
        self.assertIn("<w>", allowaudit.display("Bash(ls --oneline)", 1))

    def test_cli_hides_private_long_flag(self):
        with tempfile.TemporaryDirectory() as d:
            root = make_fixture(os.path.join(d, "projects"))
            settings = os.path.join(d, "s.json")
            with open(settings, "w") as f:
                json.dump({"permissions": {"allow": ["Bash(./deploy --acmecorp-prod)",
                                                     "Bash(git log --acmecorp-prod)"]}}, f)
            for extra in ([], ["--json"], ["--tsv"]):
                code, out, err = run(["allow-audit", "--projects", root, "--settings",
                                      settings] + extra)
                self.assertEqual(code, 0, err)
                self.assertNotIn("acmecorp", out, extra)


class DestructiveFlagFormTests(unittest.TestCase):
    """A rule gets the destructive flag when its wildcard covers a form that can delete,
    overwrite or send data: rm*, sed *, cp *, awk *, git worktree*, git branch -D * ..."""

    def test_destructive_forms(self):
        for rule in ("Bash(rm*)", "Bash(rm *)", "Bash(sed *)", "Bash(sed:*)", "Bash(cp *)",
                     "Bash(cp a b)", "Bash(awk *)", "Bash(tee *)", "Bash(git worktree*)",
                     "Bash(git worktree *)", "Bash(git branch -D *)", "Bash(git stash *)",
                     "Bash(git tag*)", "Bash(aws s3 *)", "Bash(docker compose *)",
                     "Bash(gh pr *)", "Bash(sed -i s/a/b/ f)"):
            self.assertIn(allowaudit.F_DESTRUCTIVE, allowaudit.flags_for(rule), rule)
        for rule in ("Bash(xargs*)", "Bash(tmux new-session *)", "Bash(git submodule*)"):
            self.assertIn(allowaudit.F_RUNNER, allowaudit.flags_for(rule), rule)

    def test_narrow_forms_not_flagged(self):
        for rule in ("Bash(git worktree list)", "Bash(git worktree list *)",
                     "Bash(git stash list *)", "Bash(sed -n 1p f)", "Bash(awk '{print}' f)",
                     "Bash(git status:*)", "Bash(git branch --show-current)"):
            self.assertNotIn(allowaudit.F_DESTRUCTIVE, allowaudit.flags_for(rule), rule)
