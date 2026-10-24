"""hook-runs: do the configured hooks run? Recorded hook runs per event, Claude Code version and hook
command, read from Claude Code transcripts and settings files. Read only.

Claude Code records these hook runs in a transcript:
  - attachment `hook_success` (command, exit code, duration), for example SessionStart
  - attachment `hook_additional_context` (hook name, no command), for example UserPromptSubmit
  - system record `stop_hook_summary` (one command and duration for each Stop hook, hook errors)
  - attachments of other `hook_*` types (errors, cancels)
It records no silent PreToolUse or PostToolUse run. Commands print as hash labels (h-xxxxxxxx), never
as text. Settings files print by scope only, never by path.

Python 3.9+, stdlib only.
"""
import collections
import hashlib
import json
import os
import re
from typing import Dict, List, Optional, Tuple

from . import privacy, report, sources

MANAGED = ("/Library/Application Support/ClaudeCode/managed-settings.json",
           "/etc/claude-code/managed-settings.json")
# Stop: stop_hook_summary lists every Stop hook that ran, silent ones too (0 runs = it did not run).
# Other events: a hook_success or context record exists only when the hook printed output.
EVERY_RUN = ("Stop",)
OUTPUT_ONLY_NOTE = "runs with output"
EVENT_ORDER = ("UserPromptSubmit", "Stop", "SessionStart")
_SAFE_NAME = re.compile(r"^(?:[A-Za-z]+(?::[A-Za-z_|*-]+)?|[a-z]+(?:\.[a-z_]+)+)$")


def label(command: str) -> str:
    return "h-" + hashlib.sha256(command.encode("utf-8", "replace")).hexdigest()[:8]


def _name(hook_name: Optional[str]) -> str:
    n = hook_name or "(no name)"
    return privacy.safe_label(n) if _SAFE_NAME.match(n) else label("name:" + n)


_SAFE_MATCHER = re.compile(r"^[A-Za-z0-9_*|. -]*$")


def _matcher(m: str) -> str:
    """A matcher made of tool names and `|` prints; one with a path, a rule or an MCP name prints as a hash."""
    return m if _SAFE_MATCHER.match(m) and "mcp" not in m.lower() else label("matcher:" + m).replace("h-", "m-")


def _vkey(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", v)) or (10 ** 9,)


def _pct(xs: List[int], q: float) -> Optional[int]:
    if not xs:
        return None
    xs = sorted(xs)
    k = (len(xs) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return int(round(xs[lo] + (xs[hi] - xs[lo]) * (k - lo)))


# ---------------------------------------------------------------- settings

def default_settings(cwds, home: str, managed=MANAGED) -> List[Tuple[str, str]]:
    """(scope, path) of settings files at the default places: user, managed, and each project dir
    (and its parents up to home) that a transcript cwd names."""
    out, seen = [], set()

    def add(scope, path):
        if os.path.isfile(path) and os.path.realpath(path) not in seen:
            seen.add(os.path.realpath(path))
            out.append((scope, path))

    add("user", os.path.join(home, ".claude", "settings.json"))
    add("user-local", os.path.join(home, ".claude", "settings.local.json"))
    for p in managed:
        add("managed", p)
    dirs = set()
    for c in cwds:
        d = c.split(report.WORKTREE_MARK, 1)[0].rstrip("/") or "/"
        while d not in dirs and d not in ("/", home.rstrip("/")) and len(d) > 1:
            dirs.add(d)
            d = os.path.dirname(d)
    for d in sorted(dirs):
        add("project", os.path.join(d, ".claude", "settings.json"))
        add("project-local", os.path.join(d, ".claude", "settings.local.json"))
    return out


def load_hooks(found: List[Tuple[str, str]]):
    """[(event, matcher, command, scope, project dir or None)], and the status of each file (no paths)."""
    hooks, status = [], []
    for scope, path in found:
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
            h = doc.get("hooks") if isinstance(doc, dict) else None
        except (OSError, ValueError):
            status.append({"scope": scope, "status": "unreadable", "hooks": 0})
            continue
        n = 0
        base = os.path.dirname(os.path.dirname(os.path.abspath(path))) if scope.startswith("project") else None
        for event, groups in (h.items() if isinstance(h, dict) else []):
            for g in groups if isinstance(groups, list) else []:
                if not isinstance(g, dict):
                    continue
                m = g.get("matcher") if isinstance(g.get("matcher"), str) else "*"
                for x in g.get("hooks") if isinstance(g.get("hooks"), list) else []:
                    if isinstance(x, dict) and isinstance(x.get("command"), str):
                        hooks.append((str(event), m or "*", x["command"], scope, base))
                        n += 1
        status.append({"scope": scope, "status": "ok", "hooks": n})
    return hooks, status


# ---------------------------------------------------------------- transcripts

def _files(root: str, include_subagents: bool) -> List[str]:
    return sources._files(root, include_subagents)


# Text that Claude Code puts in a user record but that the user did not type as a prompt.
NOT_TYPED = ("<task-notification", "<bash-input", "<bash-stdout", "<bash-stderr", "<local-command",
             "<command-name", "<command-message", "<command-args", "<system-reminder", "[Request interrupted",
             "Caveat: The messages below")


def _is_prompt(r: dict) -> bool:
    """A prompt the user typed in the main session (not a subagent task, a slash command, a task
    notification, `!` bash input or a meta record)."""
    if r.get("isMeta") or r.get("isCompactSummary") or r.get("isSidechain") or r.get("toolUseResult") is not None:
        return False
    c = (r.get("message") or {}).get("content") if isinstance(r.get("message"), dict) else None
    if isinstance(c, list):
        if any(isinstance(x, dict) and x.get("type") == "tool_result" for x in c):
            return False
        texts = [x.get("text") for x in c if isinstance(x, dict) and isinstance(x.get("text"), str)]
        c = texts[0] if texts else ("" if c else None)
    if not isinstance(c, str):
        return False
    return not c.lstrip().startswith(NOT_TYPED)


class _Run:
    __slots__ = ("runs", "sessions", "days", "ms", "errors", "per_event")

    def __init__(self):
        self.runs, self.sessions, self.days, self.ms, self.errors = 0, set(), set(), [], 0
        self.per_event = collections.Counter()


def _ms(x) -> Optional[int]:
    if isinstance(x, bool) or not isinstance(x, (int, float)) or x != x or x in (float("inf"), float("-inf")):
        return None
    return int(x)


def scan(root: str, settings: Optional[List[Tuple[str, str]]] = None, include_subagents: bool = False,
         since: Optional[str] = None, until: Optional[str] = None, home: Optional[str] = None,
         managed=MANAGED) -> dict:
    home = home or os.path.expanduser("~")
    root = os.path.expanduser(root)
    V = collections.defaultdict(lambda: {"sessions": set(), "prompts": 0, "prompts_with_hook": 0, "stops": 0,
                                         "stop_runs": 0, "start_runs": 0, "hook_errors": 0, "tool_calls": 0})
    cmd_runs: Dict[Tuple[str, str], _Run] = collections.defaultdict(_Run)     # (event, command)
    name_runs: Dict[Tuple[str, str], _Run] = collections.defaultdict(_Run)    # (event, hook name)
    event_days = collections.defaultdict(set)   # event -> days the event happened
    stops_at = []                                # (day, cwd) of each stop_hook_summary
    first_miss = 0
    bad = dupes = 0
    seen_uuid = set()
    cwds = set()
    files = _files(root, include_subagents)

    def add_run(x, sid, day, ms, key=None):
        x.runs += 1
        x.sessions.add(sid)
        x.days.add(day)
        m = _ms(ms)
        if m is not None:
            x.ms.append(m)
        if key is not None:
            x.per_event[key] += 1

    for path in files:
        prompts: List[list] = []   # per typed prompt in this file: [has_hook, version]
        seen_pid = set()
        cut = False                # a typed prompt of this file is before --since
        try:
            fh = open(path, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(r, dict):
                    continue
                u = r.get("uuid")
                if isinstance(u, str):
                    if u in seen_uuid:
                        dupes += 1   # a forked or copied session repeats records: count them once
                        continue
                    seen_uuid.add(u)
                ts = r.get("timestamp")
                if not isinstance(ts, str) or len(ts) < 10:
                    continue
                day = ts[:10]
                if since and day < since:
                    if r.get("type") == "user" and _is_prompt(r):
                        cut = True
                    continue
                if until and day > until:
                    continue
                if isinstance(r.get("cwd"), str):
                    cwds.add(r["cwd"])
                if not r.get("version"):
                    continue   # queue, title and mode records carry no version and no hook data
                try:
                    ver = str(r["version"])
                    sid = r.get("sessionId") if isinstance(r.get("sessionId"), str) else "-"
                    v = V[ver]
                    v["sessions"].add(sid)
                    event_days["SessionStart"].add(day)
                    t = r.get("type")
                    if t == "user" and _is_prompt(r):
                        pid = r.get("promptId")
                        if pid is None or pid not in seen_pid:
                            seen_pid.add(pid)
                            v["prompts"] += 1
                            prompts.append([False, ver])
                            event_days["UserPromptSubmit"].add(day)
                    elif t == "assistant":
                        c = (r.get("message") or {}).get("content") if isinstance(r.get("message"), dict) else None
                        if isinstance(c, list):
                            v["tool_calls"] += sum(isinstance(x, dict) and x.get("type") == "tool_use" for x in c)
                    elif t == "attachment" and isinstance(r.get("attachment"), dict):
                        a = r["attachment"]
                        typ = str(a.get("type") or "")
                        if not typ.startswith("hook"):
                            continue
                        ev = str(a.get("hookEvent") or "(unknown)")
                        cmd = a.get("command") if isinstance(a.get("command"), str) else None
                        if ev == "UserPromptSubmit" and prompts and typ in ("hook_success", "hook_additional_context"):
                            if not prompts[-1][0]:
                                prompts[-1][0] = True
                                V[prompts[-1][1]]["prompts_with_hook"] += 1
                        if ev == "Stop":
                            continue   # Stop runs and errors come from stop_hook_summary (no double count)
                        if "error" in typ or "cancel" in typ:
                            v["hook_errors"] += 1
                            if cmd:
                                cmd_runs[(ev, cmd)].errors += 1
                            else:
                                name_runs[(ev, _name(a.get("hookName")))].errors += 1
                            continue
                        tid = a.get("toolUseID") if isinstance(a.get("toolUseID"), str) else None
                        if typ == "hook_success" and cmd:
                            if ev == "SessionStart":
                                v["start_runs"] += 1
                            add_run(cmd_runs[(ev, cmd)], sid, day, a.get("durationMs"),
                                    (path, tid) if tid else None)
                        elif typ == "hook_additional_context" and ev != "SessionStart":
                            # a context record has no command and a shared toolUseID: no per-event count
                            add_run(name_runs[(ev, _name(a.get("hookName")))], sid, day, a.get("durationMs"))
                    elif t == "system" and r.get("subtype") == "stop_hook_summary":
                        v["stops"] += 1
                        stops_at.append((day, r.get("cwd") if isinstance(r.get("cwd"), str) else None))
                        infos = [i for i in r.get("hookInfos") or [] if isinstance(i, dict)] \
                            if isinstance(r.get("hookInfos"), list) else []
                        errs = r.get("hookErrors") if isinstance(r.get("hookErrors"), list) else []
                        v["hook_errors"] += len(errs)
                        cmds = [i.get("command") for i in infos if isinstance(i.get("command"), str)]
                        v["stop_runs"] += len(cmds)
                        key = (path, r.get("uuid") or ts)
                        for i in infos:
                            if isinstance(i.get("command"), str):
                                add_run(cmd_runs[("Stop", i["command"])], sid, day, i.get("durationMs"), key)
                        if errs and len(set(cmds)) == 1:
                            cmd_runs[("Stop", cmds[0])].errors += len(errs)
                except (AttributeError, TypeError, ValueError, KeyError):
                    bad += 1
        if not cut and len(prompts) >= 2 and not prompts[0][0] and any(p[0] for p in prompts[1:]):
            first_miss += 1

    found = settings if settings is not None else default_settings(sorted(cwds), home, managed)
    conf, status = load_hooks(found)

    rows = {}
    for ev, matcher, cmd, scope, base in conf:
        k = (ev, cmd)
        row = rows.setdefault(k, {"label": label(cmd), "event": ev, "matcher": _matcher(matcher),
                                  "in_settings": True, "scopes": [], "_dirs": set()})
        if scope not in row["scopes"]:
            row["scopes"].append(scope)
        row["_dirs"].add(base)   # None = user or managed scope: all projects
    for (ev, cmd) in cmd_runs:
        rows.setdefault((ev, cmd), {"label": label(cmd), "event": ev, "matcher": "-", "in_settings": False,
                                    "scopes": []})
    for (ev, nm) in name_runs:
        rows.setdefault((ev, "name:" + nm), {"label": nm, "event": ev, "matcher": "-", "in_settings": False,
                                             "scopes": [], "no_command": True})
    hooks = []
    for (ev, key), row in rows.items():
        x = name_runs.get((ev, key[5:])) if row.get("no_command") else cmd_runs.get((ev, key))
        if x is None:
            runs = 0 if ev in EVERY_RUN else None   # a silent SessionStart hook leaves no record
            row.update(runs=runs, sessions=0, first_day=None, last_day=None, errors=0, p50_ms=None,
                       p95_ms=None, max_runs_one_event=0)
        else:
            row.update(runs=x.runs, sessions=len(x.sessions), first_day=min(x.days) if x.days else None,
                       last_day=max(x.days) if x.days else None, errors=x.errors, p50_ms=_pct(x.ms, 0.5),
                       p95_ms=_pct(x.ms, 0.95), max_runs_one_event=max(x.per_event.values()) if x.per_event else 0)
        row.pop("no_command", None)
        row["recorded"] = ("every run" if ev in EVERY_RUN
                           else OUTPUT_ONLY_NOTE if row["runs"] is not None or ev == "SessionStart"
                           else "by hook name only" if ev == "UserPromptSubmit" else "not recorded")
        hooks.append(row)
    order = {e: i for i, e in enumerate(EVENT_ORDER)}
    hooks.sort(key=lambda h: (order.get(h["event"], 9), h["event"], not h["in_settings"], h["label"]))

    versions = []
    for ver in sorted(V, key=_vkey):
        d = dict(V[ver])
        d["sessions"] = len(d["sessions"] - {"-"})
        d["version"] = ver
        versions.append(d)

    def measure(ev, d):
        return {"UserPromptSubmit": (d["prompts"], d["prompts_with_hook"]), "Stop": (d["prompts"], d["stops"]),
                "SessionStart": (d["sessions"], d["start_runs"])}[ev]

    drops = []
    for ev in EVENT_ORDER:
        had = False
        for d in versions:
            events, runs = measure(ev, d)
            if runs > 0:
                had = True
            elif had and events > 0:
                drops.append([ev, d["version"]])
    last_event_day = {ev: max(days) for ev, days in event_days.items() if days}

    def last_stop(dirs) -> str:
        """Last Stop day in the projects a hook applies to (user and managed scope: all projects)."""
        if None in dirs or not dirs:
            days = [d for d, _ in stops_at]
        else:
            days = [d for d, c in stops_at if c and any(c == b or c.startswith(b.rstrip("/") + "/") for b in dirs)]
        return max(days) if days else ""

    for h in hooks:
        h["_last_stop"] = last_stop(h.get("_dirs") or {None}) if h["in_settings"] and h["event"] in EVERY_RUN else ""
    flags = {
        "configured_no_run": sorted(h["label"] for h in hooks if h["in_settings"] and h["event"] in EVERY_RUN
                                    and h["runs"] == 0 and h["_last_stop"]),
        "stopped": sorted(h["label"] for h in hooks if h["in_settings"] and h["event"] in EVERY_RUN and h["runs"]
                          and h["last_day"] and h["last_day"] < h["_last_stop"]),
        "first_prompt_miss_sessions": first_miss,
        "version_drop": sorted(drops, key=lambda x: (order[x[0]], _vkey(x[1]))),
        "multi_run": sorted(h["label"] for h in hooks if h["max_runs_one_event"] > 1),
    }
    for h in hooks:
        h.pop("_dirs", None)
        h.pop("_last_stop", None)
    return {"source": {"files": len(files), "include_subagents": include_subagents, "since": since,
                       "until": until, "bad_records": bad, "duplicate_records": dupes},
            "settings": status, "versions": versions, "hooks": hooks, "flags": flags,
            "last_event_day": last_event_day}


# ---------------------------------------------------------------- render

def render(s: dict, header: str, fmt: str = "table") -> str:
    if fmt == "json":
        return json.dumps(s, indent=1)
    if fmt == "tsv":
        keys = ("label", "event", "matcher", "in_settings", "runs", "sessions", "first_day", "last_day",
                "errors", "p50_ms", "p95_ms", "max_runs_one_event")
        return "\n".join(["\t".join(keys)] + ["\t".join(str(h[k]) for k in keys) for h in s["hooks"]])
    n = report._n
    dash = lambda x: "-" if x is None else x
    st = ", ".join("%s %s (%d hooks)" % (x["scope"], x["status"], x["hooks"]) for x in s["settings"]) or "none found"
    out = [header, "",
           "Source: Claude Code transcripts, %s files, subagents %s; settings files: %s"
           % (n(s["source"]["files"]), "included" if s["source"]["include_subagents"] else "not included", st),
           "Records repeated in a forked or copied session, counted once: %s; records the scan could not read: %s"
           % (n(s["source"]["duplicate_records"]), n(s["source"]["bad_records"])),
           "", "By version  [sessions, prompts, prompts with a prompt-hook record, Stop summaries, Stop hook runs, "
           "SessionStart hook runs, hook errors, tool calls]"]
    out += report._table([(d["version"], d["sessions"], d["prompts"], d["prompts_with_hook"], d["stops"],
                           d["stop_runs"], d["start_runs"], d["hook_errors"], d["tool_calls"])
                          for d in s["versions"]])
    out += ["", "By hook  [event, matcher, in settings, recorded, runs, sessions, first day, last day, errors, "
            "p50 ms, p95 ms, most runs for one event]"]
    out += report._table([(h["label"], h["event"], h["matcher"], "yes" if h["in_settings"] else "no",
                           h["recorded"], dash(h["runs"]), h["sessions"], dash(h["first_day"]), dash(h["last_day"]),
                           h["errors"], dash(h["p50_ms"]), dash(h["p95_ms"]), h["max_runs_one_event"])
                          for h in s["hooks"]])
    f = s["flags"]
    lst = lambda xs: ", ".join(xs) if xs else "-"
    out += ["", "Flags"]
    out += report._table([
        ("configured, no recorded run (Stop: every run is recorded)", len(f["configured_no_run"]),
         lst(f["configured_no_run"])),
        ("in settings, stopped (Stop: last run before the last Stop day)", len(f["stopped"]), lst(f["stopped"])),
        ("sessions where the first prompt has no prompt-hook record but a later one has",
         f["first_prompt_miss_sessions"], ""),
        ("events with zero hook records after a version with records", len(f["version_drop"]),
         lst(["%s %s" % (e, v) for e, v in f["version_drop"]])),
        ("hooks that ran more than once for one event", len(f["multi_run"]), lst(f["multi_run"]))])
    out += ["",
            "Limits",
            "  1. Claude Code records no silent PreToolUse or PostToolUse run; their runs show as '-'. A guard "
            "that never blocks looks the same as a guard that never runs.",
            "  2. A SessionStart or UserPromptSubmit hook is seen only when it prints output or fails "
            "('runs with output'); a silent hook shows 0 runs. The first-prompt and version flags assume "
            "the hook always prints. Only Stop hooks are recorded on every run, so only they get the "
            "'no recorded run' and 'stopped' flags.",
            "  3. Settings are read as they are now; the runs are past. A hook removed on purpose shows as "
            "'stopped' only if it is still in settings.",
            "  4. Plugin and mod hooks are not read from plugin files; their recorded runs show as 'in "
            "settings: no'.",
            "  5. Prompts = prompts typed in a main session; slash commands, `!` bash input, task "
            "notifications and subagent tasks are not prompts. Stop events count from prompts (one Stop per "
            "prompt turn, an estimate). A project-scope Stop hook is checked against Stop days in its project.",
            "  6. A UserPromptSubmit command hook that prints can show twice: once by hash label and once by "
            "hook name.",
            "Nothing was written."]
    return "\n".join(out)
