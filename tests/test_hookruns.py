"""P2-F acceptance: hook-runs reports recorded hook runs per event, version and hook command, and
flags hooks that never ran, stopped, skipped the first prompt, dropped after a version, or ran
twice for one event. Hash labels for commands; never command text. Synthetic data only."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from datapce_scan import cli, hookruns
from tests.helpers import write_project

CWD = "/Users/someone/src/alpha"
CMD_A = "python3 /opt/private-hooks/stop_a.py"
CMD_B = "/opt/private-hooks/stop_b.sh"
CMD_S = "/opt/private-hooks/start.sh"
CMD_U = "/opt/private-hooks/ups.sh"
CMD_G = "/opt/private-hooks/guard.sh"
CMD_C = "/opt/private-hooks/stop_c.sh"
SETTINGS = {"hooks": {
    "Stop": [{"hooks": [{"type": "command", "command": CMD_A}, {"type": "command", "command": CMD_B},
                        {"type": "command", "command": CMD_C}]}],
    "SessionStart": [{"matcher": "startup|resume", "hooks": [{"type": "command", "command": CMD_S}]}],
    "UserPromptSubmit": [{"hooks": [{"type": "command", "command": CMD_U}]}],
    "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": CMD_G}]}]}}


def rec(kind, ts, sid, ver, **kw):
    r = {"type": kind, "timestamp": ts, "sessionId": sid, "version": ver, "cwd": CWD}
    r.update(kw)
    return r


def prompt(ts, sid, ver, pid, text="PRIVATE PROMPT TEXT"):
    return rec("user", ts, sid, ver, promptId=pid, message={"role": "user", "content": text})


def ups(ts, sid, ver):
    return rec("attachment", ts, sid, ver, attachment={"type": "hook_additional_context", "hookEvent":
               "UserPromptSubmit", "hookName": "prompt.submit", "toolUseID": "x", "content": ["ctx"]})


def start(ts, sid, ver, tid, cmd=CMD_S, ms=50):
    return rec("attachment", ts, sid, ver, attachment={
        "type": "hook_success", "hookName": "SessionStart:startup", "hookEvent": "SessionStart",
        "toolUseID": tid, "command": cmd, "exitCode": 0, "durationMs": ms, "stdout": "ok", "stderr": "",
        "content": ""})


def stop(ts, sid, ver, infos, errors=()):
    return rec("system", ts, sid, ver, subtype="stop_hook_summary", hookCount=len(infos),
               hookInfos=[{"command": c, "durationMs": ms} for c, ms in infos], hookErrors=list(errors),
               preventedContinuation=False, toolUseID="t")


def tool_call(ts, sid, ver, tid):
    return rec("assistant", ts, sid, ver, message={"role": "assistant", "content": [
        {"type": "tool_use", "id": tid, "name": "Bash", "input": {"command": "ls"}}]})


def make_fixture(root):
    write_project(root, "-p", "s1", [
        start("2026-10-20T09:00:00Z", "s1", "2.1.290", "e1"),
        prompt("2026-10-20T09:00:01Z", "s1", "2.1.290", "p1"),            # first prompt: no hook record
        tool_call("2026-10-20T09:00:02Z", "s1", "2.1.290", "c1"),
        stop("2026-10-20T09:00:03Z", "s1", "2.1.290", [(CMD_A, 100), (CMD_C, 5)]),
        prompt("2026-10-20T09:01:00Z", "s1", "2.1.290", "p2"), ups("2026-10-20T09:01:00Z", "s1", "2.1.290"),
        stop("2026-10-20T09:01:03Z", "s1", "2.1.290", [(CMD_A, 120), (CMD_A, 140)]),   # ran twice
        prompt("2026-10-20T09:02:00Z", "s1", "2.1.290", "p3"), ups("2026-10-20T09:02:00Z", "s1", "2.1.290"),
    ])
    write_project(root, "-p", "s2", [
        prompt("2026-10-22T09:00:01Z", "s2", "2.1.299", "q1"),           # no session-start run: stopped
        prompt("2026-10-22T09:01:00Z", "s2", "2.1.299", "q2"),           # no prompt-hook record: drop
        {"type": "queue-operation", "timestamp": "2026-10-22T09:01:01Z", "sessionId": "s9"},   # no version
        stop("2026-10-22T09:01:03Z", "s2", "2.1.299", [(CMD_A, 90)], errors=["boom"]),
    ])
    return root


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class HookRunsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = make_fixture(os.path.join(self.tmp.name, "projects"))
        self.settings = os.path.join(self.tmp.name, "settings.json")
        with open(self.settings, "w") as f:
            json.dump(SETTINGS, f)
        self.r = hookruns.scan(self.root, [("file 1", self.settings)])
        self.hooks = {h["label"]: h for h in self.r["hooks"]}

    def tearDown(self):
        self.tmp.cleanup()

    def lab(self, cmd):
        return hookruns.label(cmd)

    def test_versions(self):
        v = {x["version"]: x for x in self.r["versions"]}
        self.assertEqual((v["2.1.290"]["prompts"], v["2.1.290"]["prompts_with_hook"]), (3, 2))
        self.assertEqual((v["2.1.299"]["prompts"], v["2.1.299"]["prompts_with_hook"]), (2, 0))
        self.assertEqual((v["2.1.290"]["stops"], v["2.1.290"]["stop_runs"]), (2, 4))
        self.assertNotIn("?", v)
        self.assertEqual(v["2.1.290"]["start_runs"], 1)
        self.assertEqual(v["2.1.299"]["hook_errors"], 1)

    def test_per_hook(self):
        a = self.hooks[self.lab(CMD_A)]
        self.assertEqual((a["event"], a["in_settings"], a["runs"], a["sessions"]), ("Stop", True, 4, 2))
        self.assertEqual((a["first_day"], a["last_day"], a["errors"]), ("2026-10-20", "2026-10-22", 1))
        self.assertEqual((a["p50_ms"], a["max_runs_one_event"]), (110, 2))
        self.assertEqual(self.hooks[self.lab(CMD_B)]["runs"], 0)
        self.assertEqual(self.hooks[self.lab(CMD_G)]["runs"], None)   # PreToolUse: not recorded
        self.assertEqual(self.hooks[self.lab(CMD_G)]["recorded"], "not recorded")
        self.assertEqual(self.hooks[self.lab(CMD_A)]["recorded"], "every run")
        self.assertEqual(self.hooks[self.lab(CMD_S)]["recorded"], "runs with output")
        self.assertEqual((self.hooks[self.lab(CMD_U)]["runs"], self.hooks[self.lab(CMD_U)]["recorded"]),
                         (None, "by hook name only"))
        self.assertEqual(self.hooks["prompt.submit"]["runs"], 2)

    def test_flags(self):
        f = self.r["flags"]
        self.assertEqual(f["configured_no_run"], [self.lab(CMD_B)])
        self.assertEqual(f["stopped"], [self.lab(CMD_C)])   # SessionStart: silent runs are not recorded
        self.assertEqual(f["first_prompt_miss_sessions"], 1)
        self.assertEqual(f["version_drop"], [["UserPromptSubmit", "2.1.299"], ["SessionStart", "2.1.299"]])
        self.assertEqual(f["multi_run"], [self.lab(CMD_A)])

    def test_cli_private(self):
        code, out, err = run(["hook-runs", "--projects", self.root, "--settings", self.settings])
        self.assertEqual(code, 0, err)
        for s in ("By version", "By hook", "configured, no recorded run", "stopped", "first prompt",
                  "after a version", "more than once", "Limits", "Nothing was written",
                  self.lab(CMD_A)):
            self.assertIn(s, out)
        for s in ("private-hooks", "stop_a", "PRIVATE PROMPT", "/opt", "boom", CWD):
            self.assertNotIn(s, out)

    def test_cli_json(self):
        code, out, _ = run(["hook-runs", "--projects", self.root, "--settings", self.settings, "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["flags"]["configured_no_run"], [self.lab(CMD_B)])
        self.assertNotIn("private-hooks", out)

    def _scan(self, settings=None, **kw):
        return hookruns.scan(self.root, settings or [("file 1", self.settings)], **kw)

    def test_only_typed_prompts_count(self):
        write_project(self.root, "-q", "s3", [
            prompt("2026-10-21T09:00:00Z", "s3", "2.1.290", "r0", "<command-name>/clear</command-name>"),
            prompt("2026-10-21T09:00:01Z", "s3", "2.1.290", "r1", "<task-notification>x</task-notification>"),
            prompt("2026-10-21T09:00:02Z", "s3", "2.1.290", "r2", "<bash-input>ls</bash-input>"),
            prompt("2026-10-21T09:00:03Z", "s3", "2.1.290", "r3"), ups("2026-10-21T09:00:03Z", "s3", "2.1.290"),
            prompt("2026-10-21T09:00:04Z", "s3", "2.1.290", "r4"), ups("2026-10-21T09:00:04Z", "s3", "2.1.290")])
        sub = prompt("2026-10-21T09:00:05Z", "s3", "2.1.290", "r5")
        sub.update(isSidechain=True, agentId="a1")
        write_project(self.root, "-q", "s3", [sub], sub="agent-a1")
        r = self._scan(include_subagents=True)
        v = {x["version"]: x for x in r["versions"]}
        self.assertEqual(v["2.1.290"]["prompts"], 5)          # 3 in s1 + 2 typed in s3
        self.assertEqual(r["flags"]["first_prompt_miss_sessions"], 1)   # s1 only; s3 starts with a slash command

    def test_copied_records_count_once(self):
        src = os.path.join(self.root, "-p", "s1.jsonl")
        lines = open(src).read().splitlines()
        recs = [json.loads(l) for l in lines]
        for i, r in enumerate(recs):
            r["uuid"] = "u-%d" % i
        write_project(self.root, "-p", "s1b", recs)
        with open(src, "w") as f:
            f.write("\n".join(json.dumps(r) for r in recs) + "\n")
        r = self._scan()
        a = {h["label"]: h for h in r["hooks"]}[self.lab(CMD_A)]
        self.assertEqual(a["runs"], 4)

    def test_project_hook_stopped_uses_its_project_days(self):
        proj = os.path.join(self.tmp.name, "projA")
        os.makedirs(os.path.join(proj, ".claude"))
        ps = os.path.join(proj, ".claude", "settings.json")
        with open(ps, "w") as f:
            json.dump({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "projA-stop"}]}]}}, f)
        write_project(self.root, "-a", "pa", [
            dict(stop("2026-10-20T10:00:00Z", "pa", "2.1.290", [("projA-stop", 3)]), cwd=proj)])
        r = self._scan([("file 1", self.settings), ("project", ps)])
        self.assertNotIn(hookruns.label("projA-stop"), r["flags"]["stopped"])

    def test_since_does_not_make_a_first_prompt(self):
        write_project(self.root, "-p", "s4", [
            prompt("2026-10-20T08:00:00Z", "s4", "2.1.290", "w1"), ups("2026-10-20T08:00:00Z", "s4", "2.1.290"),
            prompt("2026-10-21T08:00:00Z", "s4", "2.1.290", "w2"),
            prompt("2026-10-21T08:01:00Z", "s4", "2.1.290", "w3"), ups("2026-10-21T08:01:00Z", "s4", "2.1.290")])
        self.assertEqual(self._scan()["flags"]["first_prompt_miss_sessions"], 1)        # s1 only
        self.assertEqual(self._scan(since="2026-10-21")["flags"]["first_prompt_miss_sessions"], 0)

    def test_bad_values_do_not_crash(self):
        bad = os.path.join(self.tmp.name, "bad2.json")
        with open(bad, "w") as f:
            json.dump({"hooks": 5}, f)
        write_project(self.root, "-z", "sz", [
            rec("system", "2026-10-20T10:00:00Z", "sz", "2.1.290", subtype="stop_hook_summary", hookCount=1,
                hookInfos=[5, {"command": CMD_A, "durationMs": float("nan")}], hookErrors=7)])
        r = self._scan([("file 1", bad)])
        self.assertGreaterEqual(r["source"]["bad_records"], 0)

    def test_silent_session_start_hook_shows_dash_and_matchers_are_safe(self):
        st = os.path.join(self.tmp.name, "st.json")
        with open(st, "w") as f:
            json.dump({"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "silent"}]}],
                                 "PreToolUse": [{"matcher": "Read(./secrets/prod.env)", "hooks": [
                                     {"type": "command", "command": "g"}]},
                                                {"matcher": "mcp__privsrv__tool", "hooks": [
                                     {"type": "command", "command": "g2"}]}]}}, f)
        r = self._scan([("file 1", st)])
        h = {x["label"]: x for x in r["hooks"]}
        self.assertIsNone(h[hookruns.label("silent")]["runs"])
        out = hookruns.render(r, "h")
        for leak in ("prod.env", "secrets", "privsrv"):
            self.assertNotIn(leak, out)

    def test_missing_tool_use_id_is_not_multi_run(self):
        write_project(self.root, "-p", "s1", [start("2026-10-20T09:05:00Z", "s1", "2.1.290", None),
                                              start("2026-10-20T09:06:00Z", "s1", "2.1.290", None)])
        self.assertEqual(self._scan()["flags"]["multi_run"], [self.lab(CMD_A)])

    def _workflow_file(self):
        d = os.path.join(self.root, "-p", "s1", "subagents", "workflows", "wf_1")
        os.makedirs(d)
        with open(os.path.join(d, "a.jsonl"), "w") as f:
            f.write(json.dumps(stop("2026-10-21T09:00:00Z", "s1", "2.1.290", [(CMD_B, 7)])) + "\n")

    def test_workflow_subagent_files_count_with_include_subagents(self):
        self._workflow_file()
        r = self._scan(include_subagents=True)
        b = {h["label"]: h for h in r["hooks"]}[self.lab(CMD_B)]
        self.assertEqual(b["runs"], 1)
        self.assertNotIn(self.lab(CMD_B), r["flags"]["configured_no_run"])

    def test_default_reads_top_level_files_only(self):
        self._workflow_file()
        write_project(self.root, "-p", "s1", [stop("2026-10-21T09:01:00Z", "s1", "2.1.290", [(CMD_B, 8)])],
                      sub="agent-a1")
        self.assertEqual(hookruns._files(self.root, False),
                         [os.path.join(self.root, "-p", "s1.jsonl"), os.path.join(self.root, "-p", "s2.jsonl")])
        r = self._scan()
        self.assertEqual({h["label"]: h for h in r["hooks"]}[self.lab(CMD_B)]["runs"], 0)
        self.assertEqual(r["flags"]["configured_no_run"], [self.lab(CMD_B)])

    def test_bad_settings_file_is_skipped(self):
        bad = os.path.join(self.tmp.name, "bad.json")
        with open(bad, "w") as f:
            f.write("{not json")
        r = hookruns.scan(self.root, [("file 1", bad)])
        self.assertEqual(r["settings"][0]["status"], "unreadable")


if __name__ == "__main__":
    unittest.main()
