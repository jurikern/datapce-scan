"""Claude Code permission-rule syntax: parse, Bash prefix match, subcommand split (P2-A, P2-B)."""
import unittest

from datapce_scan import ccrules


class ParseRuleTests(unittest.TestCase):
    def test_tool_and_specifier(self):
        self.assertEqual(ccrules.parse_rule("Bash(npm test:*)"), ("Bash", "npm test *"))
        self.assertEqual(ccrules.parse_rule("Bash"), ("Bash", None))
        self.assertEqual(ccrules.parse_rule("Bash(*)"), ("Bash", None))
        self.assertEqual(ccrules.parse_rule("WebFetch(domain:example.com)"),
                         ("WebFetch", "domain:example.com"))
        self.assertEqual(ccrules.parse_rule("mcp__github__get_*"), ("mcp__github__get_*", None))

    def test_bad_rule(self):
        self.assertIsNone(ccrules.parse_rule(""))
        self.assertIsNone(ccrules.parse_rule("Bash(unclosed"))


class BashMatchTests(unittest.TestCase):
    """Rows of the docs table at code.claude.com/docs/en/permissions#wildcard-patterns."""

    def m(self, spec, cmd):
        return ccrules.bash_spec_matches(spec, cmd)

    def test_docs_rows(self):
        self.assertTrue(self.m("npm run build", "npm run build"))
        self.assertFalse(self.m("npm run build", "npm run build --watch"))
        self.assertTrue(self.m("npm run *", "npm run test --watch"))
        self.assertTrue(self.m("npm run *", "npm run"))
        self.assertFalse(self.m("npm run *", "npm install"))
        self.assertTrue(self.m("git log * main", "git log --oneline main"))
        self.assertFalse(self.m("git log * main", "git log main"))
        self.assertTrue(self.m("git * main", "git push origin main"))
        self.assertTrue(self.m("ls *", "ls -la"))
        self.assertTrue(self.m("ls *", "ls"))
        self.assertFalse(self.m("ls *", "lsof"))
        self.assertTrue(self.m("ls*", "lsof"))
        self.assertTrue(self.m("* --help *", "npm --help x"))
        self.assertFalse(self.m("* --help *", "npm --help"))

    def test_word_boundary_after_subcommand(self):
        self.assertTrue(self.m("git commit *", "git commit -m x"))
        self.assertFalse(self.m("git commit *", "git commit-tree x"))

    def test_all(self):
        self.assertTrue(self.m(None, "anything at all"))


class SplitTests(unittest.TestCase):
    def argvs(self, text):
        subs = ccrules.subcommands(text)
        return None if subs is None else [s.argv for s in subs]

    def test_operators(self):
        self.assertEqual(self.argvs("cd a && git status | head -3; npm test"),
                         [["cd", "a"], ["git", "status"], ["head", "-3"], ["npm", "test"]])

    def test_documented_wrappers_only(self):
        self.assertEqual(self.argvs("timeout 30 npm test"), [["npm", "test"]])
        self.assertEqual(self.argvs("nohup nice -n 5 pytest -q"), [["pytest", "-q"]])
        self.assertEqual(self.argvs("xargs grep x"), [["grep", "x"]])
        # not stripped by Claude Code: sudo, env, xargs with flags
        self.assertEqual(self.argvs("sudo rm -rf x"), [["sudo", "rm", "-rf", "x"]])
        self.assertEqual(self.argvs("xargs -n1 grep x"), [["xargs", "-n1", "grep", "x"]])

    def test_nested_substitution(self):
        got = self.argvs("echo $(git rev-parse HEAD)")
        self.assertIn(["git", "rev-parse", "HEAD"], got)

    def test_assignment_kept(self):
        subs = ccrules.subcommands("FOO=1 npm test")
        self.assertEqual(subs[0].argv, ["npm", "test"])
        self.assertEqual(subs[0].assigns, {"FOO": "1"})

    def test_unparseable(self):
        self.assertIsNone(ccrules.subcommands("echo 'unclosed"))
        self.assertIsNone(ccrules.subcommands("npm test &&"))


class ReadOnlyTests(unittest.TestCase):
    def test_documented_set(self):
        for argv in (["ls", "-la"], ["cat", "f"], ["grep", "-r", "x", "."], ["cd", "a"],
                     ["git", "status"], ["git", "log", "-3"], ["find", ".", "-name", "x"]):
            self.assertTrue(ccrules.is_read_only(argv), argv)

    def test_not_read_only(self):
        for argv in (["git", "commit", "-m", "x"], ["find", ".", "-delete"],
                     ["find", ".", "-exec", "rm", "{}", ";"], ["npm", "test"], ["rm", "x"]):
            self.assertFalse(ccrules.is_read_only(argv), argv)


if __name__ == "__main__":
    unittest.main()


class CallMatchTests(unittest.TestCase):
    def test_path_patterns(self):
        pm = ccrules.path_matches
        self.assertTrue(pm("~/.ssh/**", "/h/.ssh/id_rsa", home="/h"))
        self.assertTrue(pm(".env", "/a/b/.env"))
        self.assertTrue(pm("//etc/*", "/etc/hosts"))
        self.assertFalse(pm("//etc/*", "/etc/a/b"))
        self.assertTrue(pm("./src/**", "/w/src/a/b.py", cwd="/w"))
        self.assertFalse(pm("./src/**", "/w/lib/a.py", cwd="/w"))

    def test_call_matches(self):
        cm = ccrules.call_matches
        self.assertEqual(cm("Bash(rm:*)", "Bash", "cd /t && rm -rf /t/b", None), ["rm -rf /t/b"])
        self.assertEqual(cm("Read", "Read", None, "/a"), ["Read"])
        self.assertEqual(cm("WebFetch(domain:example.com)", "WebFetch", None,
                            "https://example.com/x"), ["WebFetch"])
        self.assertEqual(cm("WebFetch(domain:example.com)", "WebFetch", None,
                            "https://evil.com/example.com"), [])
        self.assertEqual(cm("mcp__github__get_*", "mcp__github__get_issue", None, None),
                         ["mcp__github__get_issue"])
        self.assertEqual(cm("mcp__github", "mcp__github__x", None, None), ["mcp__github__x"])
        self.assertEqual(cm("Edit(./src/**)", "Edit", None, "/w/src/a.py", cwd="/w"), ["Edit"])


class DocsSemanticsTests(unittest.TestCase):
    """Review finding 4: matching as code.claude.com/docs/en/permissions documents it."""

    def cm(self, *a, **kw):
        return ccrules.call_matches(*a, **kw)

    def test_a_edit_rules_cover_all_edit_tools_write_path_rules_never_match(self):
        self.assertEqual(self.cm("Edit(./src/**)", "Write", None, "/w/src/a.py", cwd="/w"),
                         ["Write"])
        self.assertEqual(self.cm("Edit(./src/**)", "NotebookEdit", None, "/w/src/a.ipynb",
                                 cwd="/w"), ["NotebookEdit"])
        self.assertEqual(self.cm("Write(./src/**)", "Write", None, "/w/src/a.py", cwd="/w"), [])
        self.assertEqual(self.cm("Glob(./src/**)", "Glob", None, "/w/src", cwd="/w"), [])
        self.assertEqual(self.cm("Write", "Write", None, "/w/x"), ["Write"])
        self.assertEqual(self.cm("Read(./src/**)", "Grep", None, "/w/src/a", cwd="/w"), ["Grep"])

    def test_b_slash_path_anchors_at_the_settings_source(self):
        pm = ccrules.path_matches
        self.assertTrue(pm("/src/**", "/w/src/a.py", cwd="/w"))
        self.assertFalse(pm("/src/**", "/w/src/a.py", cwd="/w", anchor="/h/.claude"))
        self.assertTrue(pm("/src/**", "/h/.claude/src/a", cwd="/w", anchor="/h/.claude"))
        self.assertEqual(self.cm("Edit(/src/**)", "Edit", None, "/w/src/a.py", cwd="/w",
                                 anchor="/h/.claude"), [])

    def test_c_bare_patterns_match_at_or_under_cwd_only(self):
        pm = ccrules.path_matches
        self.assertTrue(pm(".env", "/w/a/.env", cwd="/w"))
        self.assertFalse(pm(".env", "/other/.env", cwd="/w"))
        self.assertTrue(pm("*.env", "/w/a/b.env", cwd="/w"))
        self.assertTrue(pm("src/**", "/w/src/app.ts", cwd="/w"))
        self.assertFalse(pm("src/**", "/w/vendor/pkg/src/lib.js", cwd="/w"))  # allow rule

    def test_d_webfetch_domains(self):
        def wf(dom, url):
            return self.cm("WebFetch(domain:%s)" % dom, "WebFetch", None, url) == ["WebFetch"]
        self.assertTrue(wf("*", "https://any.host.org/x"))
        self.assertTrue(wf("example.*", "https://example.org/"))
        self.assertFalse(wf("example.*", "https://example.evil.com/"))
        self.assertTrue(wf("*.example.com", "https://a.b.example.com/"))
        self.assertFalse(wf("*.example.com", "https://example.com/"))
        self.assertTrue(wf("Example.com.", "https://EXAMPLE.com./x"))

    def test_e_commands_as_written_and_env_assignments(self):
        self.assertEqual(self.cm("Bash(git push *)", "Bash", "git 'push' origin main", None), [])
        self.assertEqual(self.cm("Bash(npm test *)", "Bash", "FOO=1 npm test", None), [])
        self.assertEqual(self.cm("Bash(npm test *)", "Bash", "NODE_ENV=test npm test", None),
                         ["npm test"])
        self.assertTrue(self.cm("Bash(git commit *)", "Bash", "git commit -m 'a b'", None))

    def test_f_unanchored_allow_globs_are_skipped(self):
        self.assertEqual(self.cm("mcp__*", "mcp__github__x", None, None), [])
        self.assertEqual(self.cm("*", "Read", None, "/a"), [])
        self.assertEqual(self.cm("mcp__gi*__x", "mcp__github__x", None, None), [])
        self.assertEqual(self.cm("mcp__github__x(a)", "mcp__github__x", None, None), [])
        self.assertEqual(self.cm("mcp__github__*", "mcp__github__x", None, None),
                         ["mcp__github__x"])

    def test_g_prefix_rules_cannot_approve_exec_wrappers_or_find_actions(self):
        self.assertEqual(self.cm("Bash(find *)", "Bash", "find . -delete", None), [])
        self.assertEqual(self.cm("Bash(find *)", "Bash", "find . -exec rm {} ;", None), [])
        self.assertEqual(self.cm("Bash(find . -delete)", "Bash", "find . -delete", None),
                         ["find . -delete"])
        self.assertEqual(self.cm("Bash(watch *)", "Bash", "watch ls", None), [])
        self.assertEqual(self.cm("Bash(find *)", "Bash", "find . -name x", None),
                         ["find . -name x"])


class CompoundRedirectTests(unittest.TestCase):
    """Fix round 2, item I4: a redirect after a compound closer (done, }, ), fi) is kept."""

    def test_output_redirects_after_closers(self):
        for cmd in ("for f in a; do echo $f; done > out.txt", "(echo hi) > out.txt",
                    "if true; then echo; fi > out", "{ echo a; } >> log.txt",
                    "while true; do break; done 2> err.log"):
            subs = ccrules.subcommands(cmd)
            self.assertTrue(any(ccrules.writes_file(s) for s in subs), cmd)
            self.assertFalse(all(ccrules.sub_read_only(s) for s in subs), cmd)

    def test_input_redirects_after_closers(self):
        for cmd in ("while read l; do echo $l; done < .env", "{ cat; } < .env"):
            subs = ccrules.subcommands(cmd)
            self.assertIn(("<", ".env"), [r for s in subs for r in s.redirects], cmd)

    def test_secret_touch_and_allow_suggest_see_them(self):
        import tempfile
        from unittest import mock
        import os
        from datapce_scan import allowsuggest, secrettouch, sources
        from tests.helpers import assistant_line, bash, write_project
        home, cwd = "/Users/someone", "/Users/someone/src/alpha"
        cmds = ["while read l; do echo $l; done < .env", "{ cat; } < .env",
                "for f in a; do echo $f; done > out.txt", "(echo hi) > out.txt",
                "if true; then echo; fi > out"]
        with tempfile.TemporaryDirectory() as d:
            write_project(d, "-Users-someone-src-alpha", "c1", [
                assistant_line("2026-10-22T10:00:00Z", "c1", cwd,
                               [bash("c%d" % k, c) for k, c in enumerate(cmds)])])
            with mock.patch.dict(os.environ, {"HOME": home}):
                res = sources.read_claude_code(d)
                st = secrettouch.scan(res, home)
                sg = allowsuggest.suggest(res, [], home)
            self.assertEqual({r["path"]: r["reads"] for r in st["files"]},
                             {".env (repo alpha)": 2})
            self.assertEqual(sg["relevant_calls"], 3)
            self.assertEqual(sg["covered_calls"], 0)
            self.assertEqual(sg["rejected"][allowsuggest.R_REDIRECT], 3)


def _oracle_bash(spec, command):
    """The round-1 regex matcher, kept as a test oracle for short inputs."""
    import re
    if "*" not in spec:
        return command == spec
    if spec.count("*") == 1 and spec.endswith(" *"):
        return bool(re.match(r"^%s(?: .*)?$" % re.escape(spec[:-2]), command, re.S))
    return bool(re.match("^" + ".*".join(re.escape(p) for p in spec.split("*")) + "$",
                         command, re.S))


def _oracle_glob(pat, path):
    import re
    rx = re.escape(pat).replace(r"\*\*/", "(?:.*/)?").replace(r"\*\*", ".*")
    rx = rx.replace(r"\*", "[^/]*").replace(r"\?", "[^/]")
    if pat.endswith("/**"):
        rx = "(?:%s|%s)" % (rx, re.escape(pat[:-3]))
    return bool(re.match("^" + rx + "$", path))


class LinearMatchTests(unittest.TestCase):
    """Fix round 2, item M2: wildcard and path matching are linear: an 8 KB subcommand and a
    1 KB path finish in < 1 s on adversarial rules."""

    def test_bash_wildcard_8kb(self):
        import time
        cmd = "a" * 8192
        for spec in ("a*a*a*b", "a*a*a*a*a*a*a*b", "*a*a*a*a*a*", "a *", "a*a*a*a"):
            t0 = time.perf_counter()
            got = ccrules.bash_spec_matches(spec, cmd)
            self.assertLess(time.perf_counter() - t0, 1.0, spec)
            self.assertEqual(got, spec in ("*a*a*a*a*a*", "a*a*a*a"), spec)

    def test_path_1kb(self):
        import time
        path = "/" + "a/" * 512
        for pat in ("//**/**/**/**/b", "//**/a**/a**/b", "//*a*a*a*b/**", "//**/a/**/a/**/"):
            t0 = time.perf_counter()
            got = ccrules.path_matches(pat, path)
            self.assertLess(time.perf_counter() - t0, 1.0, pat)
            self.assertEqual(got, pat == "//**/a/**/a/**/", pat)

    def test_same_answers_as_the_regex_oracle(self):
        import random
        rnd = random.Random(20261023)
        for _ in range(3000):
            spec = "".join(rnd.choice("ab *") for _ in range(rnd.randint(1, 7)))
            cmd = "".join(rnd.choice("ab ") for _ in range(rnd.randint(0, 8)))
            self.assertEqual(ccrules.bash_spec_matches(spec, cmd), _oracle_bash(spec, cmd),
                             (spec, cmd))
        for _ in range(3000):
            pat = "/" + "".join(rnd.choice(["a", "b", "/", "*", "**", "**/", "?"])
                                for _ in range(rnd.randint(1, 6)))
            if rnd.random() < 0.2:
                pat += "/**"
            path = "/" + "".join(rnd.choice("ab/") for _ in range(rnd.randint(0, 8)))
            self.assertEqual(ccrules.path_matches("/" + pat, path), _oracle_glob(pat, path),
                             (pat, path))


class RedirectRuleTests(unittest.TestCase):
    """a redirect is a no-op only for /dev/null, or for an fd copy or close
    (>& or <& with an all-digit or - target). Bash writes a file for every other output
    redirect: >&file and &>file write stdout and stderr; > 5 and > - write files 5 and -."""

    def test_parser_forms(self):
        for cmd, want in (("x >&file", (">&", "file")), ("x &>file", ("&>", "file")),
                          ("x >&2", (">&", "2")), ("x 2>&1", (">&", "1")),
                          ("x > 5", (">", "5")), ("x >|file", (">|", "file")),
                          ("x &>>file", ("&>>", "file")), ("x >&-", (">&", "-")),
                          ("x <&3", ("<&", "3")), ("x > -", (">", "-"))):
            self.assertEqual(ccrules.subcommands(cmd)[0].redirects, (want,), cmd)

    def test_no_op_redirect(self):
        for op, target in ((">&", "2"), (">&", "1"), (">&", "-"), ("<&", "3"), ("<&", "-"),
                           ("<&", "10"), (">", "/dev/null"), (">>", "/dev/null"),
                           ("&>", "/dev/null"), ("&>>", "/dev/null"), (">&", "/dev/null")):
            self.assertTrue(ccrules.no_op_redirect(op, target), (op, target))
        for op, target in ((">&", "file"), (">&", "~/.bashrc"), ("&>", "file"), ("&>", "2"),
                           ("&>", "-"), ("&>>", "file"), (">", "5"), (">>", "5"), (">", "-"),
                           (">|", "file"), (">|", "5"), (">", "out.txt"), (">&", "²"),
                           (">&", "")):
            self.assertFalse(ccrules.no_op_redirect(op, target), (op, target))

    def test_writes_file(self):
        for cmd in ("uptime >& ~/.bashrc", "launchctl list >&out.txt", "echo x &>f",
                    "echo x &>>f", "echo x > 5", "echo x >> 5", "echo x > -", "echo x >|f",
                    "echo x &>2", "echo x &> -", "echo x >& out 2>&1", "echo x 2>&1 >&out"):
            sub = ccrules.subcommands(cmd)[0]
            self.assertTrue(ccrules.writes_file(sub), cmd)
            self.assertFalse(ccrules.sub_read_only(sub), cmd)
        for cmd in ("ls >&2", "ls 2>&1", "ls >&-", "ls 2>&-", "cat <&3", "ls >& 2",
                    "ls > /dev/null", "ls &>/dev/null", "ls >/dev/null 2>&1", "cat < in.txt"):
            sub = ccrules.subcommands(cmd)[0]
            self.assertFalse(ccrules.writes_file(sub), cmd)
            self.assertTrue(ccrules.sub_read_only(sub), cmd)


class AssignmentOnlyTests(unittest.TestCase):
    """A command of assignments only keeps its redirect (X=1 > f writes f) and its PATH or
    IFS write."""

    def test_assignment_only_redirect(self):
        for cmd in ("X=1 > .env", "A=1 B=2 >> out.txt", "true && X=1 >f"):
            subs = ccrules.subcommands(cmd)
            self.assertTrue(any(ccrules.writes_file(s) for s in subs), cmd)
        self.assertTrue(any(ccrules.writes_special(s) for s in ccrules.subcommands("PATH=/x")))
        self.assertTrue(any(ccrules.writes_special(s)
                            for s in ccrules.subcommands("cd /w && IFS=, ")))
        self.assertEqual(ccrules.subcommands("X=1"), [])


class StdDeviceRedirectTests(unittest.TestCase):
    """/dev/stdin, /dev/stdout, /dev/stderr and /dev/fd/N name a file descriptor, not a file.
    <&word with a word that is not digits or - is an error in bash (ambiguous redirect)."""

    def test_std_devices_write_no_file(self):
        for cmd in ("echo x > /dev/stderr", "echo x >/dev/stdout", "echo x >> /dev/stderr",
                    "echo x > /dev/fd/2", "echo x >&/dev/stderr", "echo x 2>/dev/fd/1"):
            sub = ccrules.subcommands(cmd)[0]
            self.assertFalse(ccrules.writes_file(sub), cmd)
            self.assertTrue(ccrules.sub_read_only(sub), cmd)
        for cmd in ("echo x > /dev/tty", "echo x > /dev/fd/x", "echo x > /dev/stderr.log",
                    "echo x > /dev/stderr && echo y > out.txt"):
            subs = ccrules.subcommands(cmd)
            self.assertTrue(any(ccrules.writes_file(s) for s in subs), cmd)

    def test_opens_file(self):
        for op, target in (("<&", ".env"), ("<&", "3"), ("<<<", "x"), ("<<", "EOF"),
                           (">", "/dev/stdout"), (">", "/dev/null"), (">&", "2")):
            self.assertFalse(ccrules.opens_file(op, target), (op, target))
        for op, target in ((">&", ".env"), ("<", ".env"), (">", "/dev/tty"), ("&>", "f")):
            self.assertTrue(ccrules.opens_file(op, target), (op, target))

    def test_replay_text_keeps_std_device_redirects(self):
        from datapce_scan import allowsuggest
        sub = ccrules.subcommands("echo x > /dev/stderr")[0]
        self.assertIn("/dev/stderr", allowsuggest.replay_text(sub))
