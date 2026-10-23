"""Counts and the three output formats (table, tsv, json). Counts and labels only.

Python 3.9+, stdlib only.
"""
import collections
import hashlib
import json
import os
from typing import Dict, List, Optional, Tuple

from . import __version__, families as families_mod, privacy, rules as rules_mod, shellparse
from .sources import ReadResult

PRIVACY_LINE = "read-only, local, nothing sent, no command text printed"
LOCAL_FAMILIES_WARNING = ("WARNING: --show-local-families is on. Command family names below can "
                          "include private script or tool names. Do not share this output.")
WORKTREE_MARK = "/.claude/worktrees/"


def header() -> str:
    return "datapce-scan %s | %s" % (__version__, PRIVACY_LINE)


def repo_label(cwd: Optional[str], home: str, hashed: bool = False) -> str:
    if not cwd:
        return "(unknown)"
    path = cwd.rstrip("/") or "/"
    if WORKTREE_MARK in path:
        path = path.split(WORKTREE_MARK, 1)[0]
    if rules_mod.is_temp_path(path):
        return "(temp dir)"
    if home and path == home.rstrip("/"):
        return "(home)"
    if hashed:
        return "r-" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:8]
    return privacy.safe_label(os.path.basename(path) or "/")


def _tool_label(name: str) -> str:
    if name.startswith("mcp__"):
        parts = name.split("__")
        return privacy.safe_label("mcp:" + (parts[1] if len(parts) > 1 else "?"))
    return privacy.safe_label(name)


def _top(counter: collections.Counter, n: Optional[int], extra_names: int = 0,
         extra_count: int = 0) -> List[List]:
    """Top n rows; the rest (plus an extra bucket of hidden names) in one "(other: N)" row."""
    items = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    head, tail = (items, []) if n is None or len(items) <= n else (items[:n], items[n:])
    rows = [[k, v] for k, v in head]
    names, count = len(tail) + extra_names, sum(v for _, v in tail) + extra_count
    if names:
        rows.append(["(other: %d)" % names, count])
    return rows


def summarize(res: ReadResult, home: str, hash_repos: bool = False, top: Optional[int] = 10,
              local_families: bool = False) -> dict:
    """One rule for a Bash call everywhere: a tool call named "Bash", with or without a command."""
    tools, fams, repos, days, hidden = (collections.Counter() for _ in range(5))
    sessions, hours = set(), set()
    bash = no_cmd = simple = fallbacks = 0
    for c in res.calls:
        tools[_tool_label(c.tool)] += 1
        repos[repo_label(c.cwd, home, hash_repos)] += 1
        days[c.ts[:10]] += 1
        hours.add(c.ts[:13])
        if c.session:
            sessions.add(c.session)
        if c.tool != "Bash":
            continue
        bash += 1
        if c.command is None:
            no_cmd += 1
            continue
        parsed = shellparse.parse(c.command)
        fallbacks += 1 if parsed.fallback else 0
        for sc in parsed:
            simple += 1
            fam = privacy.safe_label(shellparse.family(sc.argv))
            if local_families or families_mod.is_public(fam):
                fams[fam] += 1
            else:
                hidden[fam] += 1
    day_keys = sorted(days)
    return {
        "privacy": PRIVACY_LINE,
        "version": __version__,
        "source": {"agent": "Claude Code", "files": res.files, "bad_lines": res.bad_lines,
                   "duplicate_tool_calls": res.duplicates,
                   "subagents_included": res.include_subagents,
                   "first_day": day_keys[0] if day_keys else None,
                   "last_day": day_keys[-1] if day_keys else None, "clock": "UTC"},
        "local_families_shown": local_families,
        "totals": {"tool_calls": len(res.calls), "bash_calls": bash,
                   "bash_calls_without_command": no_cmd, "simple_commands": simple,
                   "parse_fallbacks": fallbacks, "sessions": len(sessions),
                   "active_hours": len(hours), "days": len(days), "files": res.files},
        "tools": _top(tools, top),
        "families": _top(fams, top, len(hidden), sum(hidden.values())),
        "repos": _top(repos, top),
        "days": [[d, days[d]] for d in day_keys],
    }


def replay(res: ReadResult, ruleset, home: str, examples: int = 0) -> dict:
    return replay_many(res, [ruleset], home, examples)[0]


def replay_many(res: ReadResult, rulesets, home: str, examples: int = 0) -> List[dict]:
    """Replay each rule set over every past Bash call. One parse per call for all sets."""
    k = len(rulesets)
    denies = [collections.Counter() for _ in range(k)]
    asks = [collections.Counter() for _ in range(k)]
    temp = [collections.Counter() for _ in range(k)]
    hdoc = [collections.Counter() for _ in range(k)]
    ex: List[Dict[str, List[str]]] = [collections.defaultdict(list) for _ in range(k)]
    errors = [0] * k
    hours = set()
    bash = no_cmd = 0
    for c in res.calls:
        if c.tool != "Bash":
            continue
        bash += 1
        hours.add(c.ts[:13])
        if c.command is None:
            no_cmd += 1
            continue
        try:
            ctx = rules_mod.Context(c.command, c.cwd, home)
        except Exception:  # count, never stop the scan
            for i in range(k):
                errors[i] += 1
            continue
        for i, rs in enumerate(rulesets):
            try:
                v = rs.evaluate_ctx(ctx)
            except Exception:
                errors[i] += 1
                continue
            if v.action == "deny":
                denies[i][v.rule] += 1
                if v.temp_target:
                    temp[i][v.rule] += 1
                if v.heredoc_only:
                    hdoc[i][v.rule] += 1
            elif v.action == "ask":
                asks[i][v.rule] += 1
            if v.action != "pass" and examples and len(ex[i][v.rule]) < examples:
                ex[i][v.rule].append(c.command)
    out = []
    nh = len(hours)
    for i, rs in enumerate(rulesets):
        nd, nt, nhd = sum(denies[i].values()), sum(temp[i].values()), sum(hdoc[i].values())
        meta = rs.meta
        lab = privacy.safe_label
        r = {
            "name": rs.name,
            "ruleset": {"source_url": meta.get("source_url"), "licence": meta.get("licence"),
                        "fetched": meta.get("fetched"), "reuse": meta.get("reuse"),
                        "attribution": meta.get("attribution") or meta.get("source_url"),
                        "upstream_commit": meta.get("upstream_commit"), "sha256": rs.sha256,
                        "rules": len(rs.rules)},
            "bash_calls": bash, "bash_calls_without_command": no_cmd, "bash_hours": nh,
            "errors": errors[i],
            "denies": nd, "asks": sum(asks[i].values()),
            "denies_per_bash_hour": round(nd / nh, 3) if nh else 0.0,
            "temp_target_denies": nt,
            "temp_target_share": round(nt / nd, 3) if nd else 0.0,
            "heredoc_only_denies": nhd,
            "heredoc_only_share": round(nhd / nd, 3) if nd else 0.0,
            "denies_by_rule": [[lab(n), v] for n, v in _top(denies[i], None)],
            "temp_by_rule": {lab(n): v for n, v in temp[i].items()},
            "heredoc_by_rule": {lab(n): v for n, v in hdoc[i].items()},
            "asks_by_rule": [[lab(n), v] for n, v in _top(asks[i], None)],
        }
        if examples:
            r["_examples"] = dict(ex[i])
        out.append(r)
    return out


# ---------------------------------------------------------------- renderers

def _n(x) -> str:
    return "{:,}".format(x) if isinstance(x, int) else str(x)


def _pct(a: int, b: int) -> str:
    return "%.1f%%" % (100.0 * a / b) if b else "-"


def _table(rows: List[Tuple], indent: str = "  ") -> List[str]:
    if not rows:
        return [indent + "(none)"]
    w0 = max(len(str(r[0])) for r in rows)
    ws = [max(len(str(r[i])) for r in rows) for i in range(1, len(rows[0]))]
    out = []
    for r in rows:
        cells = [str(r[0]).ljust(w0)] + [str(c).rjust(ws[i]) for i, c in enumerate(r[1:])]
        out.append(indent + "  ".join(cells))
    return out


def render_summary(s: dict, fmt: str = "table") -> str:
    warn = s.get("local_families_shown")
    if fmt == "json":
        d = {"warning": LOCAL_FAMILIES_WARNING} if warn else {}
        d.update(sorted(s.items()))  # the warning comes first
        return json.dumps(d, indent=1)
    if fmt == "tsv":
        rows = ["# " + header()] + (["# " + LOCAL_FAMILIES_WARNING] if warn else [])
        rows.append("section\tkey\tvalue")
        for k, v in s["source"].items():
            rows.append("source\t%s\t%s" % (k, v))
        for k, v in s["totals"].items():
            rows.append("totals\t%s\t%s" % (k, v))
        for sec in ("tools", "families", "repos", "days"):
            for k, v in s[sec]:
                rows.append("%s\t%s\t%s" % (sec, k, v))
        return "\n".join(rows)
    src, t = s["source"], s["totals"]
    lines = [header()] + ([LOCAL_FAMILIES_WARNING] if warn else []) + [""]
    span = "%s to %s (UTC)" % (src["first_day"], src["last_day"]) if src["first_day"] else "no data"
    lines.append("Source: %s transcripts, %s files, %s, subagents %s"
                 % (src["agent"], _n(src["files"]), span,
                    "included" if src["subagents_included"] else "not included"))
    lines += ["", "Totals"]
    lines += _table([("tool calls", _n(t["tool_calls"])), ("Bash calls", _n(t["bash_calls"])),
                     ("simple commands in Bash calls", _n(t["simple_commands"])),
                     ("sessions", _n(t["sessions"])),
                     ("active hours (UTC clock hours with a tool call)", _n(t["active_hours"])),
                     ("days", _n(t["days"]))])
    for title, sec, base in (("Tools", "tools", t["tool_calls"]),
                             ("Bash command families (first word%s)"
                      % ("" if warn else "; names off the public list are in other"),
                      "families", t["simple_commands"]),
                             ("Repos (directory basename)", "repos", t["tool_calls"])):
        lines += ["", "%s  [calls, share]" % title]
        lines += _table([(k, _n(v), _pct(v, base)) for k, v in s[sec]])
    days = s["days"][-14:]
    lines += ["", "Days (UTC, last %d)  [tool calls]" % len(days)]
    lines += _table([(k, _n(v)) for k, v in days])
    return "\n".join(lines)


def render_replay(results: List[dict], fmt: str = "table") -> str:
    clean = [{k: v for k, v in r.items() if not k.startswith("_")} for r in results]
    if fmt == "json":
        return json.dumps({"privacy": PRIVACY_LINE, "version": __version__, "rulesets": clean},
                          indent=1, sort_keys=True)
    if fmt == "tsv":
        rows = ["# " + header(), "ruleset\tsection\tkey\tvalue"]
        for r in clean:
            for k in ("bash_calls", "bash_hours", "denies", "asks", "errors",
                      "denies_per_bash_hour", "temp_target_denies", "temp_target_share",
                      "heredoc_only_denies", "heredoc_only_share"):
                rows.append("%s\ttotals\t%s\t%s" % (r["name"], k, r[k]))
            for k in ("licence", "source_url", "fetched", "reuse"):
                rows.append("%s\tsource\t%s\t%s" % (r["name"], k, r["ruleset"][k]))
            for k, v in r["denies_by_rule"]:
                rows.append("%s\tdeny\t%s\t%s" % (r["name"], k, v))
                rows.append("%s\tdeny_temp\t%s\t%s" % (r["name"], k, r["temp_by_rule"].get(k, 0)))
                rows.append("%s\tdeny_heredoc_only\t%s\t%s"
                            % (r["name"], k, r["heredoc_by_rule"].get(k, 0)))
            for k, v in r["asks_by_rule"]:
                rows.append("%s\task\t%s\t%s" % (r["name"], k, v))
        return "\n".join(rows)
    lines = [header(), "Replay: what each rule set would have done to past Bash calls. "
                       "Nothing was blocked; this is a count."]
    for r in clean:
        m = r["ruleset"]
        lines += ["", "Rule set: %s  (%d rules; licence %s; %s; fetched %s)"
                  % (r["name"], m["rules"], m["licence"], m["attribution"], m["fetched"])]
        lines += _table([
            ("Bash calls", _n(r["bash_calls"])),
            ("Bash hours (UTC clock hours with a Bash call)", _n(r["bash_hours"])),
            ("denies", _n(r["denies"])),
            ("asks", _n(r["asks"])),
            ("denies per Bash hour", "%.3f" % r["denies_per_bash_hour"]),
            ("denies with a temp-dir target (likely false)",
             "%s (%s)" % (_n(r["temp_target_denies"]), _pct(r["temp_target_denies"], r["denies"]))),
            ("denies that match heredoc text only (likely false)",
             "%s (%s)" % (_n(r["heredoc_only_denies"]),
                          _pct(r["heredoc_only_denies"], r["denies"]))),
        ])
        if r["errors"]:
            lines += _table([("calls the matcher could not read", _n(r["errors"]))])
        if r["denies_by_rule"]:
            lines += ["  denies by rule  [denies, temp-dir target, heredoc text only]"]
            lines += _table([(k, _n(v), _n(r["temp_by_rule"].get(k, 0)),
                              _n(r["heredoc_by_rule"].get(k, 0)))
                             for k, v in r["denies_by_rule"]], indent="    ")
        if r["asks_by_rule"]:
            lines += ["  asks by rule"]
            lines += _table([(k, _n(v)) for k, v in r["asks_by_rule"]], indent="    ")
    return "\n".join(lines)


def render_examples(results: List[dict], home: str, width: int = 160) -> str:
    lines = ["", "WARNING: The lines below show command text from your own logs. They are for this "
                 "terminal only. E-mail addresses and secret-like values are masked, but other "
                 "private text can show. Do not share or paste these lines.",
             "Examples of matched calls:"]
    for r in results:
        for rule, cmds in sorted(r.get("_examples", {}).items()):
            for c in cmds:
                t = privacy.redact(" ".join(c.split()), home)
                if len(t) > width:
                    t = t[:width - 3] + "..."
                lines.append("  [%s] %s: %s" % (r["name"], rule, t))
    return "\n".join(lines)
