"""allow-audit: replay standing permissions.allow rules over past calls. Read only.

Settings files are read from paths given with --settings, or from the default Claude Code
locations (user, user-local, managed, and project / project-local settings of every project
directory seen in the transcripts). Files are opened in read mode only.

For each allow rule: past calls it matched (Bash rules match subcommands, as Claude Code does),
past matches that a packaged guard rule set denies, and flags for broad forms. Rule text
prints only in public shapes (families.public_mask): tool name, public program, listed
subcommand, one-letter or listed flag, `*`. Every other word shows as <w>; a hidden rule has
an index id, never a hash or a length. Settings file paths are never printed.

Python 3.9+, stdlib only.
"""
import collections
import json
import os
from typing import Dict, List, Optional, Tuple

from . import allowsuggest as sug, ccrules, families, report, rules as rules_mod, secrettouch
from .sources import ReadResult

F_ALL = "all commands"
F_PROGWILD = "wildcard in the program position (any program)"
F_ANYSUB = "any subcommand (wildcard before the subcommand)"
F_DESTRUCTIVE = "destructive program (can delete, overwrite or send data)"
F_RUNNER = "runner (runs the command it is given)"
F_DROPPED = ("dropped while auto mode is on (interpreter, package-manager run, shell, Agent, "
             "Monitor, PowerShell(*))")
F_TOOL = "all uses of a tool"
F_BROADPATH = "all files under / or home"
F_ONEOFF = "one-off exact command (likely saved from a prompt)"
F_UNUSED = "unused (0 past matches)"
F_SKIPPED = "never matches (Claude Code skips or never applies this rule form)"
FLAG_ORDER = (F_ALL, F_PROGWILD, F_DESTRUCTIVE, F_RUNNER, F_ANYSUB, F_DROPPED, F_TOOL,
              F_BROADPATH, F_ONEOFF, F_SKIPPED, F_UNUSED)

MANAGED = ("/Library/Application Support/ClaudeCode/managed-settings.json",
           "/etc/claude-code/managed-settings.json")
_ONEOFF_CHARS = set("/\"'=&|;$<>`")
READ_ONLY_EXTRA = {"printf", "rg", "less", "more", "jq"}


def default_settings(res: ReadResult, home: str,
                     managed: Tuple[str, ...] = MANAGED) -> List[Tuple[str, str]]:
    """(scope, path) of the settings files that exist at the default locations."""
    out, seen = [], set()

    def add(scope, path):
        if os.path.isfile(path):
            real = os.path.realpath(path)
            if real not in seen:
                seen.add(real)
                out.append((scope, path))

    add("user", os.path.join(home, ".claude", "settings.json"))
    add("user-local", os.path.join(home, ".claude", "settings.local.json"))
    for p in managed:
        add("managed", p)
    dirs = set()
    for c in res.calls:
        if not c.cwd:
            continue
        d = c.cwd.split(report.WORKTREE_MARK, 1)[0].rstrip("/") or "/"
        while d not in dirs and d not in ("/", home.rstrip("/")) and len(d) > 1:
            dirs.add(d)
            d = os.path.dirname(d)
    for d in sorted(dirs):
        add("project", os.path.join(d, ".claude", "settings.json"))
        add("project-local", os.path.join(d, ".claude", "settings.local.json"))
    return out


def load_settings(found: List[Tuple[str, str]], home: str = "",
                  hash_repos: bool = False) -> List[dict]:
    files = []
    for scope, path in found:
        label = scope
        if scope.startswith("project"):
            label = "%s %s" % (scope, report.repo_label(
                os.path.dirname(os.path.dirname(path)), home, hash_repos))
        # the directory a `/path` rule anchors at (docs: "Where a pattern anchors"); None =
        # the working directory (project, project-local; managed: not documented)
        anchor = None
        if scope in ("user", "user-local"):
            anchor = os.path.join(home or os.path.expanduser("~"), ".claude")
        elif scope.startswith("file"):
            anchor = os.path.dirname(os.path.abspath(path))
        entry = {"scope": scope, "label": label, "allow": [], "deny": 0, "ask": 0, "error": None,
                 "anchor": anchor}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            perms = doc.get("permissions", {}) if isinstance(doc, dict) else {}
            perms = perms if isinstance(perms, dict) else {}
            bad = []
            for key in ("allow", "deny", "ask"):
                v = perms.get(key, [])
                if v is None:
                    v = []
                if not isinstance(v, list):
                    bad.append(key)
                    v = []
                if key == "allow":
                    entry["allow"] = [r for r in v if isinstance(r, str)]
                else:
                    entry[key] = len(v)
            if bad:
                entry["error"] = "not a list: " + ", ".join(bad)
        except (OSError, ValueError) as e:
            entry["error"] = type(e).__name__
        files.append(entry)
    return files


# Programs that write a file with any arguments (cp target, tee files).
WRITERS = {"cp", "tee", "install"}
# Programs that can overwrite or run code with some arguments (sed -i, awk system() or
# print > file, sort -o, tar -x): destructive when the rule has a wildcard.
WRITERS_WITH_ARGS = {"sed", "gsed", "awk", "gawk", "mawk", "nawk", "sort", "tar", "perl"}
# (program, subcommand) pairs with a destructive form below them (git worktree remove,
# git branch -D, git stash drop, aws s3 rm, docker compose down -v, gh pr merge ...).
DESTRUCTIVE_UNDER = {("git", "worktree"), ("git", "branch"), ("git", "stash"), ("git", "tag"),
                     ("git", "remote"), ("git", "submodule"), ("git", "notes"), ("aws", "s3"),
                     ("docker", "compose"), ("gh", "pr"), ("gh", "issue"), ("gh", "gist"),
                     ("gh", "secret"), ("gh", "variable"), ("gh", "label"), ("gh", "run"),
                     ("gh", "workflow"), ("gh", "cache"), ("kubectl", "rollout"),
                     ("npm", "cache"), ("brew", "services")}
# (program, subcommand) pairs with a form below them that runs a given command.
RUNNER_UNDER = {("tmux", "new-session"), ("tmux", "new-window"), ("tmux", "split-window"),
                ("git", "submodule")}


def _covers_under(words: List[str]) -> bool:
    """The rule has a wildcard in the subcommand word, or after it with only flags between:
    it can match any form below that subcommand (git worktree*, git branch -D *)."""
    if len(words) < 2:
        return False
    if "*" in words[1]:
        return True
    for w in words[2:]:
        if "*" in w:
            return True
        if not w.startswith("-"):
            return False
    return False


def _base(word: str) -> str:
    w = word.rstrip("*")
    return sug._VERSION.sub("", w).rstrip("-.") or w


def flags_for(rule: str) -> List[str]:
    pr = ccrules.parse_rule(rule)
    if pr is None:
        return []
    tool, spec = pr
    f = set()
    if ccrules.allow_glob_skipped(tool) or (tool.startswith("mcp__") and "(" in rule) \
            or (tool in ccrules.NEVER_PATH_TOOLS and spec is not None):
        return [F_SKIPPED]
    if tool == "Bash":
        if spec is None:
            return [F_ALL]
        words = spec.split()
        prog = words[0] if words else ""
        sub = words[1] if len(words) > 1 else ""
        star = "*" in spec
        if "*" in prog:
            f.add(F_PROGWILD)
        if star and (_base(prog) in sug.INTERPRETERS or _base(prog) in sug.SHELLS
                     or (prog, sub) in sug.PM_RUN):
            f.add(F_DROPPED)
        base = _base(prog)
        if base in sug.RUNNERS or (prog, sub) in sug.RUNNER_PAIRS:
            f.add(F_RUNNER)
        if base in sug.NEVER or (prog, sub.rstrip("*")) in sug.NEVER_PAIRS:
            f.add(F_DESTRUCTIVE)
        if base in WRITERS or (star and base in WRITERS_WITH_ARGS):
            f.add(F_DESTRUCTIVE)
        if base in ("sed", "gsed") and secrettouch._sed_in_place(words):
            f.add(F_DESTRUCTIVE)
        if star and (prog, sub.rstrip("*")) in DESTRUCTIVE_UNDER and _covers_under(words):
            f.add(F_DESTRUCTIVE)
        if star and (prog, sub.rstrip("*")) in RUNNER_UNDER and _covers_under(words):
            f.add(F_RUNNER)
        if prog in sug.SUBCOMMAND_PROGRAMS and spec in (prog + " *", prog + "*"):
            f.add(F_ANYSUB)
        if not star and (len(words) >= 4 or any(ch in _ONEOFF_CHARS for ch in spec)):
            f.add(F_ONEOFF)
    elif tool.startswith("mcp__"):
        pass
    elif spec is None:
        f.add(F_TOOL)
        if tool in ("Agent", "Monitor", "PowerShell"):
            f.add(F_DROPPED)
    elif tool in ("Read", "Edit", "Write") and spec.rstrip("/") in ("//**", "~/**", "**", "/**"):
        f.add(F_BROADPATH)
    return [x for x in FLAG_ORDER if x in f]


def _shown(words: List[str]) -> Tuple[List[str], bool]:
    mask = families.public_mask(words)
    return [w if ok else families.HIDDEN for w, ok in zip(words, mask)], not all(mask)


def display(rule: str, idx: Optional[int] = None) -> str:
    """Rule text as printed. Only public-shape words print (families.public_mask): the tool
    name, a public program, a listed subcommand, a one-letter or listed flag, `*`. Every other word
    shows as <w>. No hash and no length of the rule text: the id is the rule's index."""
    rid = "" if idx is None else ", rule %d" % idx
    m = ccrules._RULE_RE.match(rule.strip()) if isinstance(rule, str) else None
    if m is None:
        return "(not a valid rule%s)" % rid
    tool, spec = m.group(1), m.group(2)
    if tool.startswith("mcp__"):
        parts = tool[5:].split("__", 1)
        server = parts[0] if parts[0] in families.MCP_PUBLIC else families.HIDDEN
        out = "mcp__" + server
        if len(parts) > 1:
            out += "__" + ("*" if parts[1] == "*" else families.HIDDEN)
        hidden = out != tool or spec is not None
        if spec is not None:
            out += "(%s)" % families.HIDDEN
        return out + (" (text hidden%s)" % rid if hidden else "")
    shown_tool = tool if tool in families.KNOWN_TOOLS else families.HIDDEN
    hidden = shown_tool != tool
    if spec is None:
        out = shown_tool
    elif tool == "Bash":
        body, suffix = (spec[:-2], ":*") if spec.endswith(":*") else (spec, "")
        words, h = _shown(body.split())
        hidden = hidden or h
        out = "%s(%s%s)" % (shown_tool, " ".join(words), suffix)
    elif spec.strip() == "*":
        out = "%s(*)" % shown_tool
    else:
        hidden = True  # paths, domains and PowerShell text can be private
        out = "%s(%s)" % (shown_tool, families.HIDDEN)
    return out + (" (text hidden%s)" % rid if hidden else "")


def audit(res: ReadResult, files: List[dict], guards: List["rules_mod.RuleSet"],
          home: str) -> dict:
    subs_of: Dict[int, Optional[List[ccrules.Sub]]] = {}
    for i, c in enumerate(res.calls):
        if c.tool == "Bash" and c.command is not None:
            subs_of[i] = ccrules.subcommands(c.command)
    verdicts: Dict[Tuple[str, Optional[str], bool], List[Tuple[str, bool]]] = {}

    def denied(sub: Optional[ccrules.Sub], text: str,
               cwd: Optional[str]) -> List[Tuple[str, bool]]:
        """Guard denies of one matched subcommand: (guard rule id, likely false). A command
        with an output redirect to a file is never read-only."""
        argv = sub.argv if sub is not None else None
        ro = bool(argv) and not ccrules.writes_file(sub) and not ccrules.writes_special(sub) \
            and (ccrules.is_read_only(argv) or argv[0] in READ_ONLY_EXTRA)
        key = (text, cwd, ro)
        if key not in verdicts:
            ctx = rules_mod.Context(text, cwd, home)
            verdicts[key] = [("%s %s" % (g.name, v.rule), ro or v.temp_target or v.heredoc_only)
                             for g in guards for v in [g.evaluate_ctx(ctx)] if v.action == "deny"]
        return verdicts[key]

    rows = []
    rid = 0
    guard_hits = collections.Counter()
    for f in files:
        for rule in f["allow"]:
            pr = ccrules.parse_rule(rule)
            calls = destructive = likely_false = 0
            gr = collections.Counter()
            for i, c in enumerate(res.calls):
                if pr is None:
                    break
                if pr[0] == "Bash":
                    if c.tool != "Bash":
                        continue
                    if c.command is None:
                        hit = [] if pr[1] is not None else [(None, None)]
                    elif pr[1] is None or subs_of[i] is None:
                        # a rule for every command: replay the whole call, so pipeline rules
                        # (curl | bash) see the full text
                        hit = [(None, c.command)] if pr[1] is None else []
                    else:
                        hit = [(s, sug.replay_text(s))
                               for s in subs_of[i] if ccrules.allow_matches(pr[1], s)]
                    if not hit:
                        continue
                    calls += 1
                    real, false = set(), set()
                    for sub, t in hit:
                        if t is not None:
                            for gid, lf in denied(sub, t, c.cwd):
                                (false if lf else real).add(gid)
                    if real:
                        destructive += 1
                        gr.update(real)
                    elif false:
                        likely_false += 1
                elif ccrules.call_matches(rule, c.tool, c.command, c.target, c.cwd, home,
                                          f.get("anchor")):
                    calls += 1
            fl = flags_for(rule)
            if calls == 0:
                fl.append(F_UNUSED)
            guard_hits.update(gr)
            rid += 1
            rows.append({"id": rid, "scope": f["label"], "rule_raw": rule,
                         "rule": display(rule, rid),
                         "calls": calls, "destructive": destructive, "likely_false": likely_false,
                         "guard_rules": [k for k, _ in sorted(gr.items(),
                                                              key=lambda kv: (-kv[1], kv[0]))[:3]],
                         "flags": fl})
    rows.sort(key=lambda r: (-r["destructive"], -len([x for x in r["flags"] if x != F_UNUSED]),
                             -r["calls"], r["rule"]))
    days = sorted({c.ts[:10] for c in res.calls})
    public = [{k: v for k, v in r.items() if k != "rule_raw"} for r in rows]
    return {
        "source": {"agent": "Claude Code", "files": res.files,
                   "subagents_included": res.include_subagents,
                   "first_day": days[0] if days else None, "last_day": days[-1] if days else None,
                   "clock": "UTC"},
        "settings": [{"scope": f["label"], "allow": len(f["allow"]), "deny": f["deny"],
                      "ask": f["ask"], "error": f["error"]} for f in files],
        "totals": {"settings_files": len(files), "allow_rules": len(rows),
                   "deny_rules": sum(f["deny"] for f in files),
                   "ask_rules": sum(f["ask"] for f in files),
                   "flagged": sum(1 for r in rows if r["flags"]),
                   "with_destructive_matches": sum(1 for r in rows if r["destructive"]),
                   "with_likely_false_only": sum(1 for r in rows
                                                 if r["likely_false"] and not r["destructive"]),
                   "unused": sum(1 for r in rows if r["calls"] == 0),
                   "tool_calls": len(res.calls)},
        "rules": public,
        "guard_rules_hit": dict(sorted(guard_hits.items(), key=lambda kv: (-kv[1], kv[0]))[:10]),
        "guards": [g.name for g in guards],
        "docs": list(sug.DOCS),
        "_rules_private": rows,
    }


def render(a: dict, header: str, fmt: str = "table") -> str:
    a = {k: v for k, v in a.items() if k != "_rules_private"}
    if fmt == "json":
        return json.dumps(dict(a, privacy=header.split(" | ", 1)[-1]), indent=2, sort_keys=True)
    if fmt == "tsv":
        out = ["section\tkey\tvalue"]
        out += ["totals\t%s\t%s" % kv for kv in a["totals"].items()]
        for r in a["rules"]:
            out.append("rule\t%s\t%s\t%d\t%d\t%d\t%s" % (
                r["scope"], r["rule"], r["calls"], r["destructive"], r["likely_false"],
                "; ".join(r["flags"])))
        return "\n".join(out)
    t, src = a["totals"], a["source"]
    lines = [header,
             "allow-audit: your standing permissions.allow rules, replayed over past calls. "
             "Nothing was written.", "",
             "Source: Claude Code transcripts, %d files, %s to %s (UTC), subagents %s" % (
                 src["files"], src["first_day"], src["last_day"],
                 "included" if src["subagents_included"] else "not included"), "",
             "Settings files read (read-only)  [scope, allow, deny, ask]"]
    lines += sug._table([[s["scope"], s["allow"], s["deny"], s["ask"]]
                         + ([("unreadable: " + s["error"])] if s["error"] else [])
                         for s in a["settings"]])
    lines += ["", "Totals"]
    lines += sug._table([
        ["allow rules", t["allow_rules"]],
        ["flagged (broad, destructive, runner, one-off or unused)", t["flagged"]],
        ["with past matches that a guard rule set denies", t["with_destructive_matches"]],
        ["with likely-false guard denies only (temp target, heredoc, read-only program)",
         t["with_likely_false_only"]],
        ["unused (0 past matches)", t["unused"]],
        ["past tool calls replayed", t["tool_calls"]]])
    lines += ["", "Rules  [scope, rule, past calls, calls a guard denies, likely-false denies, "
                  "flags]"]
    lines += sug._table([[r["scope"], r["rule"], r["calls"], r["destructive"], r["likely_false"],
                          "; ".join(r["flags"]) or "-"] for r in a["rules"]])
    hit = [r for r in a["rules"] if r["destructive"]]
    if hit:
        lines += ["", "Destructive matches: guard rules that denied calls an allow rule matched "
                      "(guards: %s)" % ", ".join(a["guards"])]
        lines += sug._table([[r["rule"], ", ".join(r["guard_rules"])] for r in hit])
    lines += [
        "",
        "Notes (%s ; %s):" % tuple(a["docs"]),
        "  - Deny rules win over allow rules in every scope. A flagged allow rule is still",
        "    a risk where no deny or ask rule covers the same command.",
        "  - While auto mode is on, Claude Code drops broad rules (Bash(*), PowerShell(*),",
        "    interpreter wildcards, package-manager run, Agent, Monitor); they apply again",
        "    in other modes.",
        "  - Matching follows the permissions docs: Bash words before the first * as written,",
        "    no match past a leading assignment, no prefix approval of watch or find -delete,",
        "    Edit rules for all edit tools, /path at the settings source. Limits: only NODE_ENV",
        "    counts as a known-safe variable (the full list is not published); /path rules in",
        "    managed settings anchor at the working directory (not documented); the working",
        "    directory is the one logged with each call.",
        "  - A guard deny can be a false alarm (see datapce-scan replay). The count shows",
        "    where to look, not proof of harm.",
        "  - Rule text prints only in public shapes (program, listed subcommand, one-letter",
        "    or listed flag, *). <w> marks a hidden word; 'rule N' is the rule's place in the",
        "    order of the settings files above.",
        "  - To change a rule, use /permissions or edit the settings file yourself.",
    ]
    return "\n".join(lines)
