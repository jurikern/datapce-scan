"""allow-suggest: a narrow Claude Code permissions.allow list from past Bash calls. Print only.

For each past Bash call, the command is split into subcommands as Claude Code matches allow
rules (ccrules). A call is permission-relevant if one subcommand is not in the built-in
read-only set. Deny by default, exact rules only (fix round 2): a subcommand gives a candidate
rule `Bash(<text as written>)` only if its command form is on SAFE_FORMS (a curated read-only
list), its text has no `*`, `$`, backtick, quote or backslash, and every word has a public
shape (families.public_mask: public program, listed subcommand, one-letter or listed flag). No rule
has a `*`. Every other public form goes to a "needs your judgment" list with its call count and
is never suggested. Forms that auto mode drops (interpreters,
package-manager run commands, shells), runners, and programs that delete, overwrite or send data
keep their own reasons. A candidate needs >= min_calls past calls. Then every past subcommand that
the candidate matches is replayed through the guard rule sets: one deny or ask drops the
candidate.
A candidate is dropped too if the final list would approve a past call that the user rejected
or the classifier, a safety check or a deny rule refused (all rules that approve it go).
Shell builtins with no outside effect (NEUTRAL) need no rule. This is an assumption: the docs
do not say how Claude Code treats them.

The module never writes a file. It returns counts and rule text only.

Python 3.9+, stdlib only.
"""
import collections
import re
import shlex
from typing import Dict, List, Optional, Tuple

from . import ccrules, families, rules as rules_mod, shellparse
from .sources import ReadResult

DOCS = ("https://code.claude.com/docs/en/permission-modes",
        "https://code.claude.com/docs/en/permissions")

R_PRIVATE = "private or path program name (not printed)"
R_INTERP = "interpreter (dropped in auto mode)"
R_PMRUN = "package-manager run (dropped in auto mode)"
R_SHELL = "shell, eval or source (runs any text)"
R_RUNNER = "runner (runs the command it is given)"
R_NEVER = "never suggested (can delete, overwrite or send data)"
R_OPTFIRST = "option before the subcommand (no narrow rule)"
R_BARE = "program with no subcommand (no narrow rule)"
R_FEW = "fewer past calls than --min-calls"
R_GUARD = "guard deny or ask on a past match"
R_REFUSED = "would approve a past call that was rejected or denied"
R_JUDGE = "needs your judgment (not on the curated read-only list)"
R_SHAPE = ("needs your judgment (read-only form, but a word is a path, value or private name, "
           "or the text has * $ ` \\ or a quote: no exact rule)")
_EXACT_BAD = set("*$`\"'\\\n\t\r")
R_SPECIAL = "sets, unsets or loops over PATH or IFS (prompts even if read-only)"
R_REDIRECT = ("output redirect to a file (Edit rules check the target; never counted as "
              "covered)")
NEUTRAL = {"break", "continue", "exit", "return", "true", "false", ":", "test", "[", "[[",
           "read", "shift", "wait", "unset", "set", "export", "local", "declare", "typeset",
           "readonly"}
REFUSED = ("user-rejected", "classifier-denied", "safety-check-denied", "rule-denied")

SUBCOMMAND_PROGRAMS = set("""
git gh hub git-lfs npm pnpm yarn bun deno uv pip pip3 pipx poetry pdm hatch conda mamba cargo
rustup go docker docker-compose podman kubectl helm kind minikube brew port apt apt-get dnf yum
gcloud aws az terraform tofu ansible flyctl vercel netlify heroku doctl linode-cli ollama claude
codex swift xcrun launchctl defaults security gradle mvn dotnet tmux systemctl
""".split())
INTERPRETERS = set("""
python python3 node ruby perl php lua luajit Rscript R julia ipython irb osascript tsx ts-node
""".split())
SHELLS = shellparse.SHELLS | {"eval", "exec", "source", "."}
RUNNERS = set("""
npx uvx bunx pnpx xargs env sudo doas su watch setsid ionice flock devbox direnv mise nix make
just task ssh parallel nohup open time timeout nice stdbuf command builtin noglob alias trap
""".split())
NEVER = set("""
rm rmdir unlink shred dd mkfs chmod chown chgrp kill killall pkill curl wget scp rsync nc ncat
truncate diskutil mv ln crontab openssl
""".split())
PM_RUN = {("npm", "run"), ("npm", "exec"), ("npm", "x"), ("pnpm", "run"), ("pnpm", "exec"),
          ("pnpm", "dlx"), ("yarn", "run"), ("yarn", "dlx"), ("yarn", "exec"), ("bun", "run"),
          ("bun", "x"), ("uv", "run"), ("uv", "tool"), ("poetry", "run"), ("pdm", "run"),
          ("hatch", "run"), ("cargo", "run"), ("go", "run"), ("deno", "run"), ("deno", "task"),
          ("conda", "run"), ("mamba", "run"), ("swift", "run")}
RUNNER_PAIRS = {("docker", "exec"), ("docker", "run"), ("podman", "exec"), ("podman", "run"),
                ("kubectl", "exec"), ("kubectl", "run"), ("gh", "api"), ("ollama", "run"),
                ("claude", "-p"), ("codex", "exec"), ("xcrun", "simctl"), ("tmux", "send-keys")}
NEVER_PAIRS = {("git", "push"), ("git", "reset"), ("git", "clean"), ("git", "checkout"),
               ("git", "restore"), ("git", "rebase"), ("git", "filter-branch"), ("git", "gc"),
               ("git", "update-ref"), ("git", "reflog"), ("git", "rm"), ("gh", "repo"),
               ("gh", "release"), ("kubectl", "delete"), ("kubectl", "apply"),
               ("docker", "rm"), ("docker", "rmi"), ("docker", "system"), ("docker", "volume"),
               ("terraform", "destroy"), ("terraform", "apply"), ("tofu", "destroy"),
               ("tofu", "apply"), ("brew", "uninstall"), ("security", "find-generic-password"),
               ("security", "find-internet-password"), ("security", "dump-keychain"),
               ("defaults", "delete"), ("launchctl", "unload"), ("launchctl", "bootout"),
               ("git", "config"), ("git", "switch"), ("gh", "auth"), ("claude", "plugin"),
               ("claude", "mcp"), ("claude", "config"), ("defaults", "write"),
               ("kubectl", "config"), ("aws", "configure"), ("gcloud", "auth")}
# Curated command forms that are read-only (no option that writes a file, deletes, runs a
# program or sends data, as far as this tool knows). A form only gates an exact rule; it never
# gives a `*` rule (fix round 2). brew info is out: it loads a formula file (Ruby code). Programs in the documented
# read-only set (ccrules.READ_ONLY) need no rule and are not listed. Left out on purpose:
# sort (-o, --compress-program), uniq/split/iconv/xxd/tree/shuf (output file), file (-C),
# date/hostname (set), ps (e prints the environment), printenv, rg/fd (--pre, -x), awk, sed,
# less/more, network tools (dig, host, curl), git forms with --output or exec options.
SAFE_FORMS = {tuple(f.split()) for f in """
cut|tr|rev|nl|paste|join|column|fold|expand|unexpand|tac|od|strings|comm|cmp|cksum|sum|md5
md5sum|shasum|sha1sum|sha256sum|basename|dirname|realpath|readlink|seq|sleep|whoami|id|groups
logname|uname|nproc|uptime|sw_vers|whereis|df|pgrep|jq|tsort|factor|cal
git ls-tree|git show-ref|git merge-base|git describe|git count-objects|git check-ignore
git check-attr|git name-rev|git for-each-ref|git var
gh pr view|gh pr list|gh pr diff|gh pr checks|gh pr status|gh issue view|gh issue list
gh issue status|gh run view|gh run list|gh repo view|gh release view|gh release list
gh workflow list|gh workflow view
docker ps|docker images|docker logs|docker version|docker info
npm ls|npm view|npm outdated|pip list|pip show|pip freeze|pip3 list|pip3 show|pip3 freeze
brew list|tmux ls|tmux list-sessions|tmux list-windows|tmux list-panes
tmux has-session|ollama list|ollama ps|ollama show|launchctl list|defaults read
""".replace("\n", "|").split("|") if f.strip()}
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_SUB = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
_VERSION = re.compile(r"[0-9][0-9.]*$")


def rule_for(argv: List[str], local_names: bool = False,
             written: Optional[str] = None) -> Tuple[Optional[str], str]:
    """(rule, reason). rule is an exact rule `Bash(<text>)`, or None when no rule is allowed for
    this subcommand. written is the subcommand text as written (quotes kept)."""
    prog = argv[0] if argv else ""
    if not _NAME.match(prog) or "__DPS" in prog:
        return None, R_PRIVATE
    base = _VERSION.sub("", prog).rstrip("-.") or prog
    if base in SHELLS or prog in SHELLS:
        return None, R_SHELL
    if base in INTERPRETERS:
        return None, R_INTERP
    if prog in RUNNERS:
        return None, R_RUNNER
    if prog in NEVER:
        return None, R_NEVER
    if prog in SUBCOMMAND_PROGRAMS:
        if len(argv) < 2:
            return None, R_BARE
        sub = argv[1]
        if (prog, sub) in RUNNER_PAIRS:
            return None, R_RUNNER
        if sub.startswith("-"):
            return None, R_OPTFIRST
        if not _SUB.match(sub):
            return None, R_PRIVATE
        if (prog, sub) in PM_RUN:
            return None, R_PMRUN
        if (prog, sub) in NEVER_PAIRS:
            return None, R_NEVER
    if not local_names and not families.public_program(prog):
        return None, R_PRIVATE
    form = _safe_form(argv)
    if form is None:
        return None, R_JUDGE
    text = written if written is not None else " ".join(argv)
    if any(ch in _EXACT_BAD for ch in text) or "__DPS" in text or text.split() != list(argv) \
            or not families.public_words(text.split()):
        return None, R_SHAPE
    return "Bash(%s)" % text, ""


def _safe_form(argv: List[str]) -> Optional[Tuple[str, ...]]:
    for n in (3, 2, 1):
        if len(argv) >= n and tuple(argv[:n]) in SAFE_FORMS:
            return tuple(argv[:n])
    return None


def judgment_form(argv: List[str], local_names: bool = False) -> str:
    """The command form shown in the judgment list: program, plus subcommand if it has one.
    A subcommand that is not on the fixed list (families.SUBCOMMANDS) shows as <w>, unless
    --show-local-families is on."""
    if argv[0] in SUBCOMMAND_PROGRAMS and len(argv) > 1:
        sub = argv[1]
        if not local_names and sub not in families.SUBCOMMANDS.get(argv[0], ()):
            sub = families.HIDDEN
        return "%s %s" % (argv[0], sub)
    return argv[0]


def _spec(rule: str) -> Optional[str]:
    return ccrules.parse_rule(rule)[1]


def needs_rule(sub: "ccrules.Sub") -> bool:
    argv = sub.argv
    if ccrules.writes_special(sub) or ccrules.writes_file(sub):
        return True
    if not argv:
        return False
    return not ccrules.is_read_only(argv) and argv[0] not in NEUTRAL


def _no_bash_rule(sub: "ccrules.Sub") -> Optional[str]:
    """A reason when no Bash allow rule from this tool can cover the subcommand."""
    if ccrules.writes_special(sub):
        return R_SPECIAL
    if ccrules.writes_file(sub):  # any program (fix round 2, I5)
        return R_REDIRECT
    return None


def suggest(res: ReadResult, guards: List["rules_mod.RuleSet"], home: str, min_calls: int = 3,
            local_names: bool = False) -> dict:
    relevant: List[Tuple[object, Optional[List[ccrules.Sub]]]] = []
    reasons = collections.Counter()
    cand_calls: Dict[str, set] = collections.defaultdict(set)
    cand_sessions: Dict[str, set] = collections.defaultdict(set)
    cand_subs: Dict[str, int] = collections.Counter()  # subcommands that gave the rule
    all_need: List[Tuple["ccrules.Sub", Optional[str]]] = []  # every past subcommand that needs a rule
    judge_calls: Dict[str, set] = collections.defaultdict(set)
    judge_sessions: Dict[str, set] = collections.defaultdict(set)
    bash_calls = with_text = nv_readonly = 0
    blockers = collections.Counter()
    for i, c in enumerate(res.calls):
        if c.tool != "Bash":
            continue
        bash_calls += 1
        if c.command is None:
            continue
        with_text += 1
        subs = ccrules.subcommands(c.command)
        if subs is None:
            relevant.append((c, None))
            blockers["unparseable command"] += 1
            continue
        need = [s for s in subs if needs_rule(s)]
        if not need:
            nv_readonly += 1 if c.outcome == "classifier-no-verdict" else 0
            continue
        relevant.append((c, need))
        if any(ccrules.blocks_allow(s) for s in need):
            blockers["variable assignment before the command"] += 1
        for s in need:
            all_need.append((s, c.cwd))
            why = _no_bash_rule(s)
            if why:
                reasons[why] += 1
                continue
            rule, why = rule_for(s.argv, local_names, s.written)
            if rule is None:
                reasons[why] += 1
                if why in (R_JUDGE, R_SHAPE):
                    form = judgment_form(s.argv, local_names)
                    judge_calls[form].add(i)
                    judge_sessions[form].add(c.session)
                continue
            cand_calls[rule].add(i)
            cand_sessions[rule].add(c.session)
            cand_subs[rule] += 1

    matched = _past_matches(cand_calls, all_need)
    kept, rejected_rules = [], []
    pre_denied = pre_asked = 0
    for rule in sorted(cand_calls, key=lambda r: (-len(cand_calls[r]), r)):
        if len(cand_calls[rule]) < min_calls:
            reasons[R_FEW] += cand_subs[rule]
            continue
        deny_hit, asks = None, collections.Counter()
        for text, cwd in matched[rule]:
            ctx = rules_mod.Context(text, cwd, home)
            for g in guards:
                v = g.evaluate_ctx(ctx)
                if v.action == "deny":
                    deny_hit = deny_hit or collections.Counter()
                    deny_hit["%s %s" % (g.name, v.rule)] += 1
                elif v.action == "ask":
                    asks["%s %s" % (g.name, v.rule)] += 1
        if deny_hit or asks:
            if deny_hit:
                pre_denied += 1
            else:
                pre_asked += 1
            reasons[R_GUARD] += cand_subs[rule]
            top = sorted((deny_hit or asks).items(), key=lambda kv: (-kv[1], kv[0]))
            rejected_rules.append({"rule": rule, "reason": "guard %s: " % (
                "deny" if deny_hit else "ask") + ", ".join(
                "%s (%d command%s)" % (k, n, "" if n == 1 else "s") for k, n in top[:3])})
            continue
        kept.append(rule)

    refused = [(c, need) for c, need in relevant if c.outcome in REFUSED and need is not None]
    while True:
        specs = {r: _spec(r) for r in kept}
        hit = collections.Counter()
        for c, need in refused:
            used = _approving(need, specs)
            if used:
                hit.update(used)
        if not hit:
            break
        for r, n in sorted(hit.items()):
            kept.remove(r)
            reasons[R_REFUSED] += cand_subs[r]
            rejected_rules.append({"rule": r, "reason": "%s (%d call%s)" % (
                R_REFUSED, n, "" if n == 1 else "s")})
    specs = [_spec(r) for r in kept]
    covered = 0
    nv_calls = nv_cov = 0
    nv_why = collections.Counter()
    rule_reason = {r["rule"]: r["reason"].split(":")[0].split(" (")[0] for r in rejected_rules}
    outcomes = collections.Counter()
    for c, need in relevant:
        ok = need is not None and all(
            _no_bash_rule(s) is None and any(ccrules.allow_matches(sp, s) for sp in specs)
            for s in need)
        covered += 1 if ok else 0
        if c.outcome and c.outcome not in ("ok", "error"):
            outcomes[c.outcome] += 1
        if c.outcome == "classifier-no-verdict":
            nv_calls += 1
            nv_cov += 1 if ok else 0
            if not ok:
                nv_why[_why_not(need, specs, rule_reason, local_names)] += 1
    nv_by_tool = collections.Counter(c.tool if c.tool in ("Bash", "Edit", "Write", "Agent")
                                     else "other" for c in res.calls
                                     if c.outcome == "classifier-no-verdict")

    rows = []
    for r in kept:
        nv = sum(1 for i in cand_calls[r] if res.calls[i].outcome == "classifier-no-verdict")
        rows.append({"rule": r, "calls": len(cand_calls[r]),
                     "sessions": len(cand_sessions[r] - {None}), "no_verdict_calls": nv})
    days = sorted({c.ts[:10] for c in res.calls})
    return {
        "source": {"agent": "Claude Code", "files": res.files,
                   "subagents_included": res.include_subagents,
                   "first_day": days[0] if days else None, "last_day": days[-1] if days else None,
                   "clock": "UTC"},
        "bash_calls": bash_calls, "bash_calls_with_text": with_text,
        "relevant_calls": len(relevant), "covered_calls": covered,
        "no_verdict": {"calls": nv_calls, "covered": nv_cov, "read_only_calls": nv_readonly,
                       "uncovered_reasons": dict(sorted(nv_why.items()))},
        "no_verdict_by_tool": dict(sorted(nv_by_tool.items())),
        "outcomes": dict(sorted(outcomes.items())),
        "not_coverable": dict(sorted(blockers.items())),
        "rules": rows,
        "guard_proof": {"rulesets": [g.name for g in guards],
                        "matched_commands": sum(len(matched[r]) for r in kept),
                        "denies": _recheck(kept, matched, guards, home, "deny"),
                        "asks": _recheck(kept, matched, guards, home, "ask"),
                        "candidates_dropped_by_deny": pre_denied,
                        "candidates_dropped_by_ask": pre_asked},
        "needs_judgment": [{"form": f, "calls": len(judge_calls[f]),
                            "sessions": len(judge_sessions[f] - {None})}
                           for f in sorted(judge_calls, key=lambda f: (-len(judge_calls[f]), f))],
        "rejected": dict(sorted(reasons.items())),
        "rejected_rules": rejected_rules,
        "min_calls": min_calls, "local_names": local_names,
        "settings_snippet": {"permissions": {"allow": list(kept)}},
        "docs": list(DOCS),
    }


def _why_not(need, specs, rule_reason, local_names) -> str:
    """The reason of the first subcommand that no suggested rule approves."""
    if need is None:
        return "unparseable command"
    for s in need:
        if _no_bash_rule(s):
            return _no_bash_rule(s)
        if ccrules.blocks_allow(s):
            return "variable assignment before the command"
        if any(ccrules.allow_matches(sp, s) for sp in specs):
            continue
        rule, why = rule_for(s.argv, local_names, s.written)
        if rule is None:
            return why
        return rule_reason.get(rule, R_FEW)
    return "covered"


def _approving(need: List[ccrules.Sub], specs: Dict[str, Optional[str]]) -> Optional[set]:
    """The rules that together approve every subcommand of one call, else None."""
    used = set()
    for s in need:
        if ccrules.blocks_allow(s) or _no_bash_rule(s):
            return None
        r = next((r for r, sp in specs.items() if ccrules.allow_matches(sp, s)), None)
        if r is None:
            return None
        used.add(r)
    return used


def _quote_target(t: str) -> str:
    if t.startswith("~/") and t[2:] and shlex.quote(t[2:]) == t[2:]:
        return t  # keep ~ unquoted so a guard reads it as the home directory
    return shlex.quote(t)


def replay_text(sub: "ccrules.Sub") -> str:
    """The text a guard sees for one past subcommand: the words and every redirect (fix
    round 2, I5: `cut x > ~/.bashrc` is replayed with its redirect)."""
    words = [shlex.quote(a) for a in sub.argv]
    words += ["%s %s" % (op, _quote_target(t)) for op, t in sub.redirects
              if not ccrules.no_op_redirect(op, t)]
    return " ".join(words)


def _past_matches(cand_calls, all_need) -> Dict[str, List[Tuple[str, Optional[str]]]]:
    """(replay text, cwd) of every past subcommand that needs a rule and that each candidate
    rule matches, as ccrules matches it (also subcommands that gave no rule)."""
    by_text: Dict[str, List[Tuple["ccrules.Sub", Optional[str]]]] = collections.defaultdict(list)
    for s, cwd in all_need:
        by_text[s.written].append((s, cwd))
    out: Dict[str, List[Tuple[str, Optional[str]]]] = {}
    for rule in cand_calls:
        spec = _spec(rule)
        out[rule] = [(replay_text(s), cwd) for s, cwd in by_text.get(spec, ())
                     if ccrules.allow_matches(spec, s)]
    return out


def _recheck(kept, matched, guards, home, action) -> int:
    """Independent second pass: guard verdicts of one action over the final rules' past
    matches (0 by construction; a non-zero count is a bug)."""
    n = 0
    for r in kept:
        for text, cwd in matched[r]:
            n += sum(1 for g in guards if g.evaluate(text, cwd, home).action == action)
    return n


# ---------------------------------------------------------------- output

LOCAL_WARNING = ("WARNING: --show-local-families is on. Rule text below can include private "
                 "script or tool names. Do not share this output.")


def _pct(a: int, b: int) -> str:
    return "%.1f%%" % (100.0 * a / b) if b else "n/a"


def _of(a: int, b: int) -> str:
    return "%d of %d  (%s)" % (a, b, _pct(a, b))


def _table(rows, indent="  "):
    if not rows:
        return [indent + "(none)"]
    w = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    return [indent + "  ".join(str(v).ljust(w[i]) for i, v in enumerate(r)).rstrip() for r in rows]


def render(s: dict, header: str, fmt: str = "table") -> str:
    import json
    if fmt == "json":
        return json.dumps(dict(s, privacy=header.split(" | ", 1)[-1]), indent=2, sort_keys=True)
    if fmt == "tsv":
        out = ["section\tkey\tvalue"]
        for k in ("bash_calls", "bash_calls_with_text", "relevant_calls", "covered_calls"):
            out.append("totals\t%s\t%s" % (k, s[k]))
        out.append("no_verdict\tcalls\t%d" % s["no_verdict"]["calls"])
        out.append("no_verdict\tcovered\t%d" % s["no_verdict"]["covered"])
        for r in s["rules"]:
            out.append("rule\t%s\t%d\t%d\t%d" % (r["rule"], r["calls"], r["sessions"],
                                                 r["no_verdict_calls"]))
        for k, v in s["guard_proof"].items():
            if not isinstance(v, (list, dict)):
                out.append("guard_proof\t%s\t%s" % (k, v))
        for k, v in s["rejected"].items():
            out.append("rejected\t%s\t%d" % (k, v))
        for j in s["needs_judgment"]:
            out.append("judgment\t%s\t%d\t%d" % (j["form"], j["calls"], j["sessions"]))
        return "\n".join(out)
    src = s["source"]
    p = s["guard_proof"]
    lines = [header]
    if s["local_names"]:
        lines.append(LOCAL_WARNING)
    lines += [
        "allow-suggest: a narrow permissions.allow list from your past Bash calls. "
        "Nothing was written.",
        "",
        "Source: Claude Code transcripts, %d files, %s to %s (UTC), subagents %s" % (
            src["files"], src["first_day"], src["last_day"],
            "included" if src["subagents_included"] else "not included"),
        "",
        "Coverage (Bash calls; a call is covered only if every subcommand that is not "
        "read-only matches a rule)"]
    lines += _table([
        ["Bash calls with command text", s["bash_calls_with_text"]],
        ["permission-relevant (a subcommand is not in the built-in read-only set)",
         s["relevant_calls"]],
        ["covered by the suggested rules", _of(s["covered_calls"], s["relevant_calls"])],
        ["denied with no classifier verdict (\"cannot determine the safety\")",
         s["no_verdict"]["calls"]],
        ["  of these, covered by the suggested rules",
         _of(s["no_verdict"]["covered"], s["no_verdict"]["calls"])],
    ])
    nv = s["no_verdict"]
    if nv["uncovered_reasons"]:
        lines.append("    not covered, by reason: " + ", ".join(
            "%s %d" % kv for kv in sorted(nv["uncovered_reasons"].items(),
                                          key=lambda kv: (-kv[1], kv[0]))))
    if nv["read_only_calls"]:
        lines.append("    no-verdict denials on read-only Bash calls (docs: these wait for server review; "
                     "an allow rule is not shown to help): %d"
                     % nv["read_only_calls"])
    if s["no_verdict_by_tool"]:
        lines.append("  no-verdict denials by tool: " + ", ".join(
            "%s %d" % kv for kv in s["no_verdict_by_tool"].items()))
    if s["outcomes"]:
        lines.append("  other outcomes of relevant calls: " + ", ".join(
            "%s %d" % kv for kv in s["outcomes"].items() if kv[0] != "classifier-no-verdict"))
    if s["not_coverable"]:
        lines.append("  not coverable by a prefix rule: " + ", ".join(
            "%s %d" % kv for kv in s["not_coverable"].items()))
    lines += ["", "Suggested rules (min %d past calls)  [rule, calls, sessions, no-verdict calls]"
              % s["min_calls"]]
    lines += _table([[r["rule"], r["calls"], r["sessions"], r["no_verdict_calls"]]
                     for r in s["rules"]])
    lines += ["", "Guard check: every past match of the suggested rules, replayed through %d "
              "rule sets (%s)" % (len(p["rulesets"]), ", ".join(p["rulesets"]))]
    lines += _table([["matched subcommands", p["matched_commands"]],
                     ["guard denies on these past matches", p["denies"]],
                     ["guard asks on these past matches", p["asks"]],
                     ["candidate rules dropped because a past match was denied",
                      p["candidates_dropped_by_deny"]],
                     ["candidate rules dropped because a past match was asked",
                      p["candidates_dropped_by_ask"]]])
    lines += ["  This check covers past matches only. It does not prove that a rule cannot match",
              "  a destructive command later. Each rule is one exact command (no *), seen at",
              "  least %d times, of a curated read-only form, built only from public words" % s["min_calls"],
              "  (program, listed subcommand, one-letter or listed flags)."]
    nj = s["needs_judgment"]
    lines += ["", "Needs your judgment (no exact read-only rule; never suggested)  "
                  "[command form, calls, sessions]  %d forms, %d subcommands" % (
                      len(nj), s["rejected"].get(R_JUDGE, 0) + s["rejected"].get(R_SHAPE, 0))]
    lines += _table([[j["form"], j["calls"], j["sessions"]] for j in nj[:30]])
    if len(nj) > 30:
        lines.append("  (%d more forms; see --json)" % (len(nj) - 30))
    lines += ["  Some argument forms of these programs can write, delete, run code or send",
              "  data. Write a narrow rule yourself only for a form you checked."]
    lines += ["", "Not suggested  [subcommands, reason]"]
    lines += _table([[v, k] for k, v in sorted(s["rejected"].items(), key=lambda kv: -kv[1])])
    if s["rejected_rules"]:
        lines += ["", "Dropped candidate rules  [rule, reason]"]
        lines += _table([[r["rule"], r["reason"]] for r in s["rejected_rules"]])
    lines += [
        "",
        "How the rules act (%s ; %s):" % DOCS,
        "  - In auto mode a call that matches an allow rule resolves at step 1 of the decision",
        "    order, before the classifier (exceptions: protected paths, critical rm paths,",
        "    per-command allowed domains).",
        "  - Auto mode drops broad rules: Bash(*), PowerShell(*), interpreter wildcards,",
        "    package-manager run commands, Agent and Monitor rules. No suggested rule has",
        "    these forms.",
        "  - Coverage uses the documented matching: words before the first * as written, no",
        "    match past a leading assignment (only NODE_ENV counts as known-safe; the full list",
        "    is not published), no prefix approval of watch or find -exec/-delete.",
        "  - The docs do not say that an allow rule skips server-side classifier review. A",
        "    no-verdict denial under server review can still happen for a covered call.",
        "  - An exact rule does not pin the working directory or the environment. The same",
        "    text can reach another host or run a configured program: a repo .npmrc,",
        "    pip.conf or .git/config, or PIP_INDEX_URL, NPM_CONFIG_REGISTRY, GH_HOST or GH_REPO",
        "    in the environment can redirect it.",
        "  - Limits: the guard check covers past matches only; a rule can match a new command later.",
        "    The read-only set used here is the part the docs name; the real set is larger, so",
        "    the relevant count is an upper bound. A command with an output redirect to a",
        "    file, or a PATH/IFS write, counts as permission-relevant and never as covered.",
        "    Input redirects (< file) count as read-only; the docs check them against Read",
        "    rules and the working directories, which this tool does not model. Shell",
        "    builtins such as break, exit, read and export (not on PATH or IFS) are counted",
        "    as needing no rule (an assumption, not in the docs).",
        "",
        "To use the rules, add them yourself with /permissions or in a settings file you choose:",
        json.dumps(s["settings_snippet"], indent=2),
    ]
    return "\n".join(lines)
