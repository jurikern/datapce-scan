"""P2-C acceptance: secret-touch lists tool calls that read or printed secret-shaped files or
values. Paths as safe labels and counts only; never a value. Synthetic transcripts only; the
secret-shaped values below are made up and built by concatenation."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from datapce_scan import cli, secrettouch, sources
from tests.helpers import assistant_line, bash, result_line, write_project

HOME = "/Users/someone"
CWD = HOME + "/src/alpha"
AWS_ID = "AKIA" + "ZQ7W" * 4
OPENAI = "sk-proj-" + "Q7wErTy8uIoP9aSd" * 2
GHP = "ghp_" + "Z9y8X7w6V5u4" * 3
PLACEHOLDER = "sk-live-ABCDEFGH1234567890abcd"
PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"
VALUES = (AWS_ID, OPENAI, GHP, "b3BlbnNzaC1rZXktdjEAAAAA", "acme-prod")


def make_secret_fixture(root):
    calls = [
        ("r1", "Read", {"file_path": HOME + "/.aws/credentials"}),
        ("r2", "Read", {"file_path": CWD + "/.env"}),
        ("r3", "Read", {"file_path": CWD + "/.env.example"}),
        bash("r4", "cat ~/.ssh/id_ed25519"),
        bash("r5", "grep -n TOKEN .env"),
        bash("r6", "printenv"),
        bash("r7", "security find-generic-password -s svc -w"),
        bash("r8", "curl -H 'Authorization: Bearer %s' https://api.github.com/user" % GHP),
        bash("r9", "python3 - <<'EOF'\nprint(open('.env').read())\nEOF"),
        ("r10", "Edit", {"file_path": CWD + "/a.swift", "old_string": "a",
                         "new_string": "let k = NSAttributedString.Key.font"}),
        ("r11", "Write", {"file_path": CWD + "/.env", "content": "X=1"}),
        bash("r12", "cat " + CWD + "/deploy/acme-prod.pem"),
        bash("r13", "echo test"),
        bash("r14", "git status"),
    ]
    write_project(root, "-Users-someone-src-alpha", "s1", [
        assistant_line("2026-10-20T09:00:00Z", "s1", CWD, calls[:7]),
        result_line("2026-10-20T09:00:05Z", "s1", [
            ("r1", "[default]\naws_access_key_id = %s\n" % AWS_ID, False),
            ("r2", "OPENAI_API_KEY=%s\n" % OPENAI, False),
            ("r4", PEM, False)]),
    ])
    write_project(root, "-Users-someone-src-alpha", "s2", [
        assistant_line("2026-10-21T09:00:00Z", "s2", CWD, calls[7:]),
        result_line("2026-10-21T09:00:05Z", "s2", [("r13", "key " + PLACEHOLDER, False)]),
    ])
    return root


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    out.isatty = lambda: False  # type: ignore[attr-defined]
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class KindTests(unittest.TestCase):
    def test_value_kinds(self):
        k = secrettouch.value_kinds
        self.assertEqual(k("x " + AWS_ID), {"AWS access key id": [False]})
        self.assertIn("private key block", k(PEM))
        self.assertIn("GitHub token", k(GHP))
        self.assertIn("sk- API key", k(OPENAI))
        self.assertEqual(k("key " + PLACEHOLDER), {"sk- API key": [True]})
        self.assertEqual(k("max_tokens: 12000 and TOKENS_TOTAL=1234567890123456"), {})
        self.assertEqual(k("let k = NSAttributedString.Key.font"), {})

    def test_secret_paths(self):
        f = secrettouch.secret_path
        self.assertTrue(f(HOME + "/.aws/credentials", HOME))
        self.assertTrue(f("/w/.env", HOME))
        self.assertTrue(f("/w/.env.local", HOME))
        self.assertFalse(f("/w/.env.example", HOME))
        self.assertTrue(f(HOME + "/.ssh/id_ed25519", HOME))
        self.assertFalse(f(HOME + "/.ssh/id_ed25519.pub", HOME))
        self.assertFalse(f(HOME + "/.ssh/known_hosts", HOME))
        self.assertTrue(f("/w/deploy/x.pem", HOME))
        self.assertFalse(f("NSAttributedString.Key", HOME))


class SourceKindTests(unittest.TestCase):
    def test_kinds_on_calls(self):
        with tempfile.TemporaryDirectory() as d:
            res = sources.read_claude_code(make_secret_fixture(d))
            by = {c.tool_use_id: c for c in res.calls}
            self.assertIn("AWS access key id", by["r1"].output_kinds)
            self.assertIn("GitHub token", by["r8"].input_kinds)
            self.assertEqual(by["r14"].output_kinds, ())
            self.assertEqual(by["r10"].input_kinds, ())


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = make_secret_fixture(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"HOME": HOME})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def report(self):
        return secrettouch.scan(sources.read_claude_code(self.root), HOME)

    def test_totals(self):
        t = self.report()["totals"]
        self.assertEqual(t["read_file_calls"], 5)  # r1 r2 r4 r5 r12; not r3 (.example), r9 (heredoc)
        self.assertEqual(t["write_file_calls"], 1)  # r11
        self.assertEqual(t["store_or_env_calls"], 2)  # r6 printenv, r7 keychain
        self.assertEqual(t["input_value_calls"], 1)  # r8
        self.assertEqual(t["output_value_calls"], 4)  # r1 r2 r4 r13
        self.assertEqual(t["output_placeholder_calls"], 1)  # r13

    def test_files(self):
        f = {r["path"]: r for r in self.report()["files"]}
        self.assertEqual(f["~/.aws/credentials"]["reads"], 1)
        self.assertEqual(f[".env (repo alpha)"]["reads"], 2)
        self.assertEqual(f[".env (repo alpha)"]["writes"], 1)
        self.assertEqual(f["~/.ssh/id_ed25519"]["reads"], 1)
        self.assertEqual(f["*.pem file (repo alpha)"]["reads"], 1)
        self.assertEqual(len(f), 4)

    def test_cli_never_prints_values_or_paths(self):
        for extra in ([], ["--json"], ["--tsv"]):
            code, out, err = run(["secret-touch", "--projects", self.root] + extra)
            self.assertEqual(code, 0, err)
            for leak in VALUES + (HOME, "deploy/"):
                self.assertNotIn(leak, out)
        code, out, _ = run(["secret-touch", "--projects", self.root])
        self.assertIn("~/.aws/credentials", out)
        self.assertIn("Rotate first", out)
        self.assertIn("private key block", out)
        self.assertIn("Values are never printed", out)

    def test_hash_repos(self):
        code, out, _ = run(["secret-touch", "--projects", self.root, "--hash-repos", "--json"])
        self.assertNotIn("repo alpha", out)
        self.assertIn("(repo r-", out)
        json.loads(out)


if __name__ == "__main__":
    unittest.main()


class KindSpeedTests(unittest.TestCase):
    """Review finding 3: secret-kind patterns must be linear; 2 MB adversarial text < 2 s."""
    SHAPES = ("TOKEN", "eyJ-", "eyJabcdefghij.", "SECRET_", "sk-", "PASSWORD ", "x" * 63 + "_TOKEN")

    def test_adversarial_2mb(self):
        import time
        for unit in self.SHAPES:
            text = unit * (2_000_000 // len(unit))
            t0 = time.perf_counter()
            secrettouch.value_kinds(text)
            self.assertLess(time.perf_counter() - t0, 2.0, unit)

    def test_kinds_unchanged_on_real_shapes(self):
        k = secrettouch.value_kinds
        jwt = "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12
        self.assertEqual(k("t " + jwt), {"JWT": [False]})
        self.assertEqual(k("x eyJ-" + jwt), {"JWT": [False]})
        self.assertIn("named secret assignment", k("MY_API_TOKEN=Zq7wErTy8uIoP9aSd1"))
        self.assertIn("named secret assignment", k("export db_password = 'Zq7wErTy8uIoP9aSd1'"))


class HomeVarAndRedirectTests(unittest.TestCase):
    """Review finding 5: $HOME and ${HOME} paths and < input redirects are file reads."""

    def test_home_vars_and_redirects(self):
        with tempfile.TemporaryDirectory() as d:
            write_project(d, "-Users-someone-src-alpha", "v1", [
                assistant_line("2026-10-22T10:00:00Z", "v1", CWD, [
                    bash("v1", "cat $HOME/.aws/credentials"),
                    bash("v2", "head -1 ${HOME}/.ssh/id_rsa"),
                    bash("v3", "python3 load.py < .env"),
                    bash("v4", "cd sub && sort < .env"),
                    bash("v5", "echo k=v > .env.local"),
                    bash("v6", "cat <<'EOF' > notes.txt\n.env\nEOF")])])
            s = secrettouch.scan(sources.read_claude_code(d), HOME)
            f = {r["path"]: r for r in s["files"]}
            self.assertEqual(f["~/.aws/credentials"]["reads"], 1)
            self.assertEqual(f["~/.ssh/id_rsa"]["reads"], 1)
            self.assertEqual(f[".env (repo alpha)"]["reads"], 2)
            self.assertEqual(f[".env.local (repo alpha)"]["writes"], 1)
            self.assertEqual(s["totals"]["read_file_calls"], 4)
            self.assertEqual(s["totals"]["write_file_calls"], 1)


class FdRedirectTests(unittest.TestCase):
    """>&file and &>file write the file; > <digits> and > - write files named so;
    fd copies and closes (2>&1, >&2, >&-, <&3) and /dev/null touch no file."""

    def test_repro_c(self):
        with tempfile.TemporaryDirectory() as d:
            write_project(d, "-Users-someone-src-alpha", "w1", [
                assistant_line("2026-10-22T10:00:00Z", "w1", CWD, [
                    bash("w1", "echo x >& ~/.aws/credentials")])])
            s = secrettouch.scan(sources.read_claude_code(d), HOME)
        self.assertEqual(s["totals"]["write_file_calls"], 1)
        self.assertEqual({r["path"]: r["writes"] for r in s["files"]}, {"~/.aws/credentials": 1})

    def test_redirect_paths(self):
        f = secrettouch._redirect_paths
        for cmd, want in (("echo x >& ~/.aws/credentials", [(HOME + "/.aws/credentials", "writes")]),
                          ("echo x >&.env", [(CWD + "/.env", "writes")]),
                          ("echo x &>.env", [(CWD + "/.env", "writes")]),
                          ("echo x &>>.env", [(CWD + "/.env", "writes")]),
                          ("echo x >|.env", [(CWD + "/.env", "writes")]),
                          ("echo x > 5", [(CWD + "/5", "writes")]),
                          ("echo x > -", []),  # a file named - : _resolve skips - words
                          ("echo x >&2", []), ("echo x 2>&1", []), ("echo x >&-", []),
                          ("cat <&3", []), ("echo x > /dev/null 2>&1", []),
                          ("sort < .env 2>&1", [(CWD + "/.env", "reads")]),
                          ("cat <<< x", [])):
            self.assertEqual(f(cmd, CWD, HOME), want, cmd)

    def test_fd_forms_with_secret_files(self):
        cmds = ["echo x >& ~/.aws/credentials", "echo x &> .env", "echo x >&.env",
                "echo x 2>&1 >&2", "sort < .env 2>&1"]
        with tempfile.TemporaryDirectory() as d:
            write_project(d, "-Users-someone-src-alpha", "w2", [
                assistant_line("2026-10-22T10:00:00Z", "w2", CWD,
                               [bash("w%d" % k, c) for k, c in enumerate(cmds)])])
            s = secrettouch.scan(sources.read_claude_code(d), HOME)
        f = {r["path"]: (r["reads"], r["writes"]) for r in s["files"]}
        self.assertEqual(f, {"~/.aws/credentials": (0, 1), ".env (repo alpha)": (1, 2)})
        self.assertEqual(s["totals"]["write_file_calls"], 3)
        self.assertEqual(s["totals"]["read_file_calls"], 1)


class PatternArgTests(unittest.TestCase):
    """Review finding 6: the pattern or program argument of grep, jq, sed, awk is not a file."""

    def test_patterns_are_not_reads(self):
        cmds = {"p1": "jq .data.key config.json", "p2": "grep -rn id_rsa src/",
                "p3": "sed s/id_rsa/x/ f.txt", "p4": "awk '/.env/' log.txt",
                "p5": "rg -n credentials.json docs", "p6": "grep -e id_rsa .env",
                "p7": "grep -f .env x.txt", "p8": "jq .a ~/.docker/config.json",
                "p9": "awk -F= '{print $1}' .env", "p10": "jq --arg k .pem .a f.json"}
        with tempfile.TemporaryDirectory() as d:
            write_project(d, "-Users-someone-src-alpha", "p1", [
                assistant_line("2026-10-22T10:00:00Z", "p1", CWD,
                               [bash(k, v) for k, v in cmds.items()])])
            s = secrettouch.scan(sources.read_claude_code(d), HOME)
            f = {r["path"]: r["reads"] for r in s["files"]}
            self.assertEqual(f, {".env (repo alpha)": 3, "~/.docker/config.json": 1})


class GrepRgOptionTests(unittest.TestCase):
    """Fix round 2, item I3: grep/egrep and rg have separate option tables. grep -E, -r and -T
    take no value; rg -E, -r, -t and -T do."""

    def test_option_tables(self):
        cmds = ["grep -E 'API_KEY|TOKEN' .env", "grep -r KEY .env", "grep -r KEY ~/.aws/credentials",
                "egrep -r x .env", "grep -T KEY .env", "grep -rE KEY .env", "grep -rA 2 KEY .env",
                "grep -m1 KEY .env", "fgrep -r KEY .env", "rg -r X KEY .env", "rg -t py KEY .env",
                "rg -T js KEY .env", "rg -E utf8 KEY .env", "rg -rX KEY .env",
                "rg -e KEY -g '*.py' .env"]
        with tempfile.TemporaryDirectory() as d:
            write_project(d, "-Users-someone-src-alpha", "g1", [
                assistant_line("2026-10-22T10:00:00Z", "g1", CWD,
                               [bash("g%d" % k, c) for k, c in enumerate(cmds)])])
            s = secrettouch.scan(sources.read_claude_code(d), HOME)
            f = {r["path"]: r["reads"] for r in s["files"]}
            self.assertEqual(f, {".env (repo alpha)": len(cmds) - 1, "~/.aws/credentials": 1})
            self.assertEqual(s["totals"]["read_file_calls"], len(cmds))

    def test_patterns_still_skipped(self):
        for argv, files in ((["grep", "-E", "x", "a"], ["a"]), (["rg", "-E", "utf8", "x", "a"], ["a"]),
                            (["grep", "-e", ".env", "a"], ["a"]), (["rg", "-r", ".env", "x", "a"], ["a"]),
                            (["grep", "-rA", "2", ".env", "a"], ["a"])):
            self.assertEqual(secrettouch._file_args(argv), files, argv)


def _scan_cmds(cmds, home=HOME, cwd=CWD):
    with tempfile.TemporaryDirectory() as d:
        write_project(d, "-Users-someone-src-alpha", "x1", [
            assistant_line("2026-10-22T10:00:00Z", "x1", cwd,
                           [bash("x%d" % k, c) for k, c in enumerate(cmds)])])
        return secrettouch.scan(sources.read_claude_code(d), home)


class WriteProgramTests(unittest.TestCase):
    """tee F, the destination of cp and mv, and sed -i F write the file; an assignment-only
    command keeps its redirect; one call can read and write the same file."""

    def files(self, cmds):
        s = _scan_cmds(cmds)
        return {r["path"]: (r["reads"], r["writes"]) for r in s["files"]}, s["totals"]

    def test_tee_cp_sed_write(self):
        for cmd in ("echo K=1 | tee .env", "echo K=1 | tee -a .env", "cp src.txt .env",
                    "cp -f src.txt .env", "mv new.txt .env", "X=1 > .env", "A=1 B=2 >> .env"):
            f, t = self.files([cmd])
            want = ".env (repo alpha)"
            self.assertEqual(f, {want: (0, 1)}, cmd)
            self.assertEqual((t["read_file_calls"], t["write_file_calls"]), (0, 1), cmd)

    def test_sed_in_place_reads_and_writes(self):
        # sed -i reads the file and writes it back: a read and a write (never-loosen)
        for cmd in ("sed -i s/a/b/ .env", "sed -i.bak s/a/b/ .env", "sed -i -e s/a/b/ .env",
                    "sed --in-place s/a/b/ .env", "sed -i '' s/a/b/ .env",
                    "sed -Ei s/a/b/ .env", "sed -i -f prog.sed .env"):
            f, t = self.files([cmd])
            self.assertEqual(f, {".env (repo alpha)": (1, 1)}, cmd)
            self.assertEqual((t["read_file_calls"], t["write_file_calls"]), (1, 1), cmd)
        f, t = self.files(["sed -i s/a/b/ .env ~/.aws/credentials"])
        self.assertEqual(f, {".env (repo alpha)": (1, 1), "~/.aws/credentials": (1, 1)})
        self.assertEqual((t["read_file_calls"], t["write_file_calls"]), (1, 1))
        # a program file given with -f is read, not written
        f, _ = self.files(["sed -i -f .env x.txt"])
        self.assertEqual(f, {".env (repo alpha)": (1, 0)})

    def test_cp_reads_source_and_writes_into_directory(self):
        f, _ = self.files(["cp .env backup.txt"])
        self.assertEqual(f, {".env (repo alpha)": (1, 0)})
        f, _ = self.files(["cp ~/.aws/credentials /tmp/bk/"])
        self.assertEqual(f, {"~/.aws/credentials": (1, 0), "credentials (other dir)": (0, 1)})
        f, _ = self.files(["cp -t /tmp/bk src.txt .env.local"])  # -t names a directory
        self.assertEqual(f, {".env.local (repo alpha)": (1, 0),
                             ".env.local (other dir)": (0, 1)})
        f, _ = self.files(["cp a.txt .env /tmp/bk"])  # two sources: the target is a directory
        self.assertEqual(f, {".env (repo alpha)": (1, 0), ".env (other dir)": (0, 1)})
        f, _ = self.files(["sed -n 1p .env", "sed -e s/a/b/ .env"])
        self.assertEqual(f, {".env (repo alpha)": (2, 0)})

    def test_one_call_reads_and_writes(self):
        f, t = self.files(["grep -q K .env || echo K=1 >> .env"])
        self.assertEqual(f, {".env (repo alpha)": (1, 1)})
        self.assertEqual((t["read_file_calls"], t["write_file_calls"]), (1, 1))


class PrivateNameLabelTests(unittest.TestCase):
    """A private file name under ~/.ssh or ~/.gnupg prints as an index id, never as a hash of
    the name (a short hash of a name can be found by a dictionary search)."""

    def test_index_ids_no_hash(self):
        import hashlib
        names = ("acme_deploy_key", "github-work")
        s = _scan_cmds(["cat ~/.ssh/acme_deploy_key", "cat ~/.ssh/github-work",
                        "cat ~/.ssh/acme_deploy_key",
                        "cat ~/.gnupg/private-keys-v1.d/ACMEKEYGRIP"])
        out = json.dumps(s)
        for n in names + ("ACMEKEYGRIP",):
            self.assertNotIn(n, out)
            self.assertNotIn(hashlib.sha256(n.encode()).hexdigest()[:6], out)
        f = {r["path"]: r["reads"] for r in s["files"]}
        self.assertEqual(f, {"~/.ssh/key file #1": 2, "~/.ssh/key file #2": 1,
                             "~/.gnupg/.../secret-shaped file #3": 1})


class InputPlaceholderPerKindTests(unittest.TestCase):
    """The placeholder-like count of input values is given per kind, as for output."""

    def test_per_kind(self):
        s = _scan_cmds(["echo key " + PLACEHOLDER, "echo key " + OPENAI,
                        "echo " + AWS_ID])
        v = {k["kind"]: k for k in s["values"]}
        self.assertEqual(v["sk- API key"]["input_calls"], 2)
        self.assertEqual(v["sk- API key"]["input_placeholder_calls"], 1)
        self.assertEqual(v["AWS access key id"]["input_placeholder_calls"], 0)
        self.assertEqual(s["totals"]["input_placeholder_calls"], 1)
        text = secrettouch.render(s, "h")
        self.assertIn("input placeholder-like", text)
        tsv = secrettouch.render(s, "h", "tsv")
        # new column at the end: the first fields keep their old places
        self.assertIn("value\tsk- API key\t2\t0\t0\t1", tsv)


class AmbiguousInputRedirectTests(unittest.TestCase):
    """cat <&.env opens no file (bash: ambiguous redirect): not a read."""

    def test_fd_input_word_is_not_a_read(self):
        self.assertEqual(secrettouch._redirect_paths("cat <&.env", CWD, HOME), [])
        self.assertEqual(secrettouch._redirect_paths("cat 0<&.env", CWD, HOME), [])
        s = _scan_cmds(["cat <&.env", "cat <&~/.aws/credentials"])
        self.assertEqual(s["totals"]["read_file_calls"], 0)
        self.assertEqual(s["files"], [])
        s = _scan_cmds(["echo x >&.env", "sort < .env"])
        self.assertEqual({r["path"]: (r["reads"], r["writes"]) for r in s["files"]},
                         {".env (repo alpha)": (1, 1)})


class CpSuffixOptionTests(unittest.TestCase):
    """cp and mv -S SUFFIX (also in a short group such as -fS, -bS, or attached -S.bak, and
    --suffix=SUF) take a value: the suffix is not a file argument. -t in a group takes the
    target directory."""

    def files(self, cmds):
        s = _scan_cmds(cmds)
        return {r["path"]: (r["reads"], r["writes"]) for r in s["files"]}

    def test_suffix_groups(self):
        for cmd in ("cp -fS .bak x .env", "cp -bS .bak x .env", "cp -S .bak x .env",
                    "cp -S.bak x .env", "cp -bS.bak x .env", "cp --suffix=.bak x .env",
                    "cp --suffix .bak x .env", "cp -b -S .bak x .env", "mv -fS .bak x .env"):
            self.assertEqual(self.files([cmd]), {".env (repo alpha)": (0, 1)}, cmd)
        self.assertEqual(self.files(["cp -bS .bak x ~/.ssh/id_rsa"]), {"~/.ssh/id_rsa": (0, 1)})
        self.assertEqual(self.files(["cp -fS .bak .env x.txt"]), {".env (repo alpha)": (1, 0)})

    def test_target_in_group(self):
        self.assertEqual(self.files(["cp -rt /tmp/bk .env"]),
                         {".env (repo alpha)": (1, 0), ".env (other dir)": (0, 1)})
        self.assertEqual(self.files(["cp -t/tmp/bk .env"]),
                         {".env (repo alpha)": (1, 0), ".env (other dir)": (0, 1)})

    def test_tee_has_no_value_options(self):
        self.assertEqual(self.files(["echo x | tee -t .env"]), {".env (repo alpha)": (0, 1)})
        self.assertEqual(self.files(["echo x | tee --target-directory .env"]),
                         {".env (repo alpha)": (0, 1)})

    def test_no_touch_lost_for_directory_targets_and_option_values(self):
        # a target directory with a secret-shaped name and an option value stay counted
        self.assertEqual(self.files(["cp x y ~/.aws/credentials"]), {"~/.aws/credentials": (0, 1)})
        self.assertEqual(self.files(["cp -t ~/.aws/credentials x"]), {"~/.aws/credentials": (0, 1)})
        self.assertEqual(self.files(["cp -S ~/.aws/credentials x y"]),
                         {"~/.aws/credentials": (1, 0)})
