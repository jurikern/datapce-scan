"""secret-touch: past tool calls that read or printed secret-shaped files or values. Read only.

A secret-shaped file is found by name and place (.env, credentials, ~/.ssh/id_*, *.pem, ...),
in the target of Read, Grep, Glob, Edit and Write calls, and in the arguments of Bash
subcommands (heredoc bodies are not arguments). A secret-shaped value is found by its form
(secretkinds) in the call input and in the tool result. The output holds safe path labels,
kinds and counts only: never a value, never a full path, never a private file name.

Python 3.9+, stdlib only.
"""
import collections
import hashlib
import json
import os
import posixpath
import re
from typing import Dict, List, Optional, Tuple

from . import ccrules, report, rules as rules_mod, secretkinds, shellparse

value_kinds = secretkinds.value_kinds

HOME_SECRET = {  # first directory under home -> file names in it that are secret-shaped
    ".ssh": None,  # every file except the public ones below
    ".aws": {"credentials"},
    ".kube": {"config"},
    ".docker": {"config.json"},
    ".gnupg": None,
    ".claude": {".credentials.json", "credentials.json"},
    ".codex": {"auth.json"},
    ".config": {"hosts.yml", "credentials.json", "credentials.db", "application_default_credentials.json",
                "access_tokens.db", "auth.json", "token.json"},
}
SSH_PUBLIC = {"known_hosts", "known_hosts.old", "config", "authorized_keys", "environment"}
NAMES = {".netrc", ".npmrc", ".pypirc", ".git-credentials", "credentials", "credentials.json",
         "secrets.json", "secrets.yaml", "secrets.yml", "secrets.toml", "service-account.json",
         ".htpasswd", ".pgpass", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".envrc",
         "terraform.tfvars", ".vault-token"}
ENV_SUFFIX_OK = {"local", "development", "dev", "production", "prod", "staging", "test"}
ENV_NOT_SECRET = {"example", "sample", "template", "dist", "defaults", "schema"}
EXT = {".pem": "*.pem file", ".key": "*.key file", ".p12": "*.p12 file", ".pfx": "*.pfx file",
       ".jks": "*.jks file", ".keystore": "*.keystore file", ".ppk": "*.ppk file",
       ".tfstate": "*.tfstate file"}
NOREAD = {"ls", "stat", "test", "[", "[[", "file", "du", "wc", "chmod", "chown", "touch", "rm",
          "rmdir", "mkdir", "which", "realpath", "readlink", "basename", "dirname", "echo",
          "printf", "mv", "git", "cd", "find"}
READ_TOOLS = {"Read", "Grep", "Glob", "NotebookRead"}
WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
ROTATE = {
    "private key block": "SSH or TLS private keys",
    "Anthropic API key": "Anthropic API keys",
    "sk- API key": "OpenAI-style sk- provider keys",
    "GitHub token": "GitHub tokens",
    "AWS access key id": "AWS access keys",
    "Slack token": "Slack tokens",
    "GitLab token": "GitLab tokens",
    "Google API key": "Google API keys",
    "JWT": "session tokens (JWT; check the expiry first)",
    secretkinds.NAMED_KIND: "named secrets (KEY=value) in .env-style files",
}


def _env_secret(base: str) -> bool:
    if base == ".env":
        return True
    if not base.startswith(".env."):
        return False
    parts = set(base[5:].split("."))
    return not (parts & ENV_NOT_SECRET)


def secret_path(path: str, home: str) -> bool:
    if not path or "/" not in path:
        return False
    path = posixpath.normpath(path)
    base = posixpath.basename(path)
    h = home.rstrip("/")
    if h and path.startswith(h + "/"):
        rel = path[len(h) + 1:].split("/")
        if rel[0] in HOME_SECRET and len(rel) > 1:
            names = HOME_SECRET[rel[0]]
            if rel[0] == ".ssh":
                return not base.endswith(".pub") and base not in SSH_PUBLIC
            if rel[0] == ".gnupg":
                return "private" in path or base.endswith((".key", ".gpg"))
            if base in names:
                return True
    if base in NAMES or _env_secret(base):
        return True
    ext = posixpath.splitext(base)[1]
    return ext in EXT and len(base) > len(ext)


def _generic(base: str) -> str:
    if base in NAMES:
        return base
    if base == ".env":
        return base
    if base.startswith(".env."):
        suf = base[5:]
        return base if suf in ENV_SUFFIX_OK else ".env.* file"
    ext = posixpath.splitext(base)[1]
    if ext in EXT:
        return EXT[ext]
    return "secret-shaped file #" + hashlib.sha256(base.encode("utf-8")).hexdigest()[:6]


def label(path: str, cwd: Optional[str], home: str, hash_repos: bool = False) -> str:
    """A safe label: ~/<known dir>/<generic name>, or '<generic name> (repo <label>)'."""
    path = posixpath.normpath(path)
    base = posixpath.basename(path)
    h = home.rstrip("/")
    if h and path.startswith(h + "/"):
        rel = path[len(h) + 1:].split("/")
        if rel[0] in HOME_SECRET and len(rel) > 1:
            known = HOME_SECRET[rel[0]]
            if rel[0] == ".ssh":
                name = base if base in NAMES else "key file #" + hashlib.sha256(
                    base.encode("utf-8")).hexdigest()[:6]
            elif known and base in known:
                name = base
            else:
                name = _generic(base)
            mid = "/".join(rel[1:-1])
            mid = (mid + "/") if mid in ("gh", "gcloud") else ("" if not mid else ".../")
            return "~/%s/%s%s" % (rel[0], mid, name)
        if len(rel) == 1:
            return "~/" + _generic(base)
    root = None
    if cwd:
        c = cwd.split(report.WORKTREE_MARK, 1)[0].rstrip("/")
        if path.startswith(c + "/"):
            root = c
    where = ("repo " + report.repo_label(root, home, hash_repos)) if root else "other dir"
    return "%s (%s)" % (_generic(base), where)


_HOME_VAR = re.compile(r"^(?:\$HOME|\$\{HOME\})(?=/|$)")


def _resolve(tok: str, cwd: Optional[str], home: str) -> Optional[str]:
    if tok and home:
        tok = _HOME_VAR.sub(lambda _m: "~", tok, count=1)
    if not tok or tok.startswith("-") or "$" in tok or "__DPS" in tok or "\n" in tok:
        return None
    if tok.startswith("~/"):
        return home.rstrip("/") + tok[1:]
    if tok.startswith("/"):
        return tok
    if cwd and re.match(r"^[A-Za-z0-9._@+/-]+$", tok):
        return posixpath.join(cwd, tok)
    return None


STORE_RULES = [
    ("environment dump (env, printenv, set)",
     lambda a: (a[0] in ("env", "printenv") and len(a) == 1) or (a[0] == "set" and len(a) == 1)
     or (a[0] == "printenv" and any(re.search(r"(?i)key|token|secret|pass", x) for x in a[1:]))),
    ("keychain read (security find-*-password, dump-keychain)",
     lambda a: a[0] == "security" and len(a) > 1 and a[1] in (
         "find-generic-password", "find-internet-password", "dump-keychain")
     and (a[1] == "dump-keychain" or "-w" in a or "-g" in a)),
    ("CLI token or secret print",
     lambda a: (a[:3] == ["gh", "auth", "token"])
     or (a[:2] == ["gcloud", "auth"] and len(a) > 2 and a[2].startswith("print-"))
     or (a[:3] in (["aws", "configure", "get"], ["aws", "configure", "export-credentials"]))
     or (a[:3] == ["aws", "sts", "get-session-token"])
     or (a[:3] == ["az", "account", "get-access-token"])
     or (a[0] == "op" and len(a) > 1 and a[1] in ("read", "item"))
     or (a[:2] == ["pass", "show"])
     or (a[0] == "vault" and len(a) > 1 and a[1] in ("read", "kv"))
     or (a[0] == "kubectl" and len(a) > 2 and a[1] == "get" and a[2].startswith("secret"))),
]


# Programs whose first positional argument is a pattern or a program text, not a file.
# grep and rg have separate tables (fix round 2, I3): grep -E, -r and -T take no value; rg -E
# (encoding), -r (replace), -t and -T (types) do. ag and ack use the grep table.
_PATTERN_FAMILY = {"grep": "grep", "egrep": "grep", "fgrep": "grep", "ag": "grep",
                   "ack": "grep", "rg": "rg", "sed": "sed", "gsed": "sed", "awk": "awk",
                   "gawk": "awk", "mawk": "awk", "nawk": "awk", "jq": "jq", "yq": "jq"}
_PAT_OPT = {"grep": {"-e", "--regexp"}, "rg": {"-e", "--regexp"}, "sed": {"-e", "--expression"},
            "awk": set(), "jq": set()}
_PAT_FILE = {"grep": {"-f", "--file"}, "rg": {"-f", "--file"}, "sed": {"-f", "--file"},
             "awk": {"-f", "--file"}, "jq": {"-f", "--from-file"}}
_OPT_VAL = {
    "grep": {"-A", "-B", "-C", "-m", "-d", "-D", "--include", "--exclude", "--exclude-dir",
             "--exclude-from", "--label", "--context", "--before-context", "--after-context",
             "--max-count", "--binary-files", "--devices", "--directories", "--group-separator"},
    "rg": {"-A", "-B", "-C", "-m", "-g", "-t", "-T", "-M", "-j", "-E", "-r", "-d", "--glob",
           "--iglob", "--type", "--type-not", "--type-add", "--type-clear", "--max-columns",
           "--threads", "--encoding", "--replace", "--max-depth", "--max-filesize", "--color",
           "--colors", "--context", "--before-context", "--after-context", "--max-count",
           "--sort", "--sortr", "--ignore-file", "--pre", "--pre-glob", "--path-separator",
           "--engine", "--dfa-size-limit", "--regex-size-limit", "--context-separator",
           "--field-match-separator", "--field-context-separator", "--hostname-bin",
           "--hyperlink-format"},
    "sed": {"-l"}, "awk": {"-F", "-v"}, "jq": {"--indent", "-L"}}


def _file_args(argv: List[str]) -> List[str]:
    """The arguments of one command that can be files. For grep, rg, sed, awk and jq the
    pattern or program argument is left out (unless -e or -f gave it). Short options can be
    grouped (-rA 2, -m1): the first option in a group that takes a value ends the group."""
    fam = _PATTERN_FAMILY.get(os.path.basename(argv[0]))
    if fam is None:
        return argv[1:]
    files: List[str] = []
    pos: List[str] = []
    given = False
    i = 1
    while i < len(argv):
        a = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else None
        if a == "--":
            pos.extend(argv[i + 1:])
            break
        if not a.startswith("-") or a == "-":
            pos.append(a)
            i += 1
            continue
        if a.startswith("--"):
            name, eq, val = a.partition("=")
            if name in _PAT_OPT[fam]:
                given, i = True, i + (1 if eq else 2)
            elif name in _PAT_FILE[fam]:
                given = True
                v = val if eq else nxt
                if v:
                    files.append(v)
                i += 1 if eq else 2
            elif fam == "jq" and name in ("--arg", "--argjson"):
                i += 3
            elif fam == "jq" and name in ("--slurpfile", "--rawfile"):
                if i + 2 < len(argv):
                    files.append(argv[i + 2])
                i += 3
            elif name in _OPT_VAL[fam] and not eq:
                i += 2
            else:
                i += 1
            continue
        step = 1  # a short option group: -x, -xyz, -xVALUE
        for k in range(1, len(a)):
            opt, rest = "-" + a[k], a[k + 1:]
            if opt in _PAT_OPT[fam]:
                given = True
            elif opt in _PAT_FILE[fam]:
                given = True
                v = rest or nxt
                if v:
                    files.append(v)
            elif opt not in _OPT_VAL[fam]:
                continue
            step = 1 if rest else 2
            break
        i += step
    if not given and pos:
        pos = pos[1:]
    return files + pos


def _store_kind(argv: List[str]) -> Optional[str]:
    if not argv:
        return None
    for name, test in STORE_RULES:
        if test(argv):
            return name
    return None


def _redirect_paths(command: str, cwd: Optional[str], home: str) -> List[Tuple[str, str]]:
    """(path, 'reads' or 'writes') for file redirects: < file reads, > >> &> file writes.
    Here-strings, here-docs and fd forms (2>&1, <&3) are not files. cd at the top level moves
    the directory that later relative targets resolve against."""
    subs = ccrules.subcommands(command)
    out: List[Tuple[str, str]] = []
    if not subs:
        return out
    cur = cwd
    for sub in subs:
        if sub.argv and sub.argv[0] == "cd" and sub.depth == 0:
            args = [a for a in sub.argv[1:] if not a.startswith("-")]
            nxt = _resolve(args[0], cur, home) if args else None
            cur = posixpath.normpath(nxt) if nxt else cur
        for op, target in sub.redirects:
            if op in ("<<<", "<<") or op.endswith("&") or target.isdigit() or target == "-":
                continue
            p = _resolve(target, cur, home)
            if p:
                out.append((p, "reads" if "<" in op and ">" not in op else "writes"))
    return out


def scan(res, home: str, hash_repos: bool = False) -> dict:
    files: Dict[str, dict] = {}
    stores = collections.Counter()
    kinds: Dict[str, Dict[str, set]] = collections.defaultdict(
        lambda: {"input": set(), "output": set(), "placeholder": set()})
    read_calls, write_calls, store_calls, in_calls, out_calls, out_ph = (set() for _ in range(6))
    in_ph = set()
    days = collections.Counter()
    sessions = set()

    def touch(i, c, path, how):
        lab = label(path, c.cwd, home, hash_repos)
        f = files.setdefault(lab, {"path": lab, "reads": 0, "writes": 0,
                                   "tools": collections.Counter(), "sessions": set(),
                                   "first_day": c.ts[:10], "last_day": c.ts[:10], "_calls": set()})
        if i in f["_calls"]:
            return
        f["_calls"].add(i)
        f[how] += 1
        f["tools"][c.tool] += 1
        f["sessions"].add(c.session)
        f["first_day"] = min(f["first_day"], c.ts[:10])
        f["last_day"] = max(f["last_day"], c.ts[:10])
        (read_calls if how == "reads" else write_calls).add(i)

    for i, c in enumerate(res.calls):
        before = len(read_calls) + len(write_calls) + len(store_calls) + len(in_calls) \
            + len(out_calls)
        if c.target and (c.tool in READ_TOOLS or c.tool in WRITE_TOOLS):
            p = _resolve(c.target, c.cwd, home) if not c.target.startswith("/") else c.target
            if p and secret_path(p, home):
                touch(i, c, p, "reads" if c.tool in READ_TOOLS else "writes")
        if c.tool == "Bash" and c.command:
            parsed = shellparse.parse(c.command)
            ctx = rules_mod.Context(c.command, c.cwd, home)
            for k, sc in enumerate(parsed):
                argv = sc.argv
                if not argv:
                    continue
                sk = _store_kind(argv)
                if sk:
                    stores[sk] += 1
                    store_calls.add(i)
                prog = os.path.basename(argv[0])
                if prog in NOREAD:
                    continue
                cwd = ctx.cwds[k] if k < len(ctx.cwds) else c.cwd
                for tok in _file_args(argv):
                    p = _resolve(tok, cwd, home)
                    if p and secret_path(p, home):
                        touch(i, c, p, "reads")
            for p, how in _redirect_paths(c.command, c.cwd, home):
                if secret_path(p, home):
                    touch(i, c, p, how)
        for kd in c.input_kinds:
            kinds[kd]["input"].add(i)
            in_calls.add(i)
        if c.input_kinds and set(c.input_kinds) == set(c.input_ph):
            in_ph.add(i)
        for kd in c.output_kinds:
            kinds[kd]["output"].add(i)
            out_calls.add(i)
            if kd in c.output_ph:
                kinds[kd]["placeholder"].add(i)
        if c.output_kinds and set(c.output_kinds) == set(c.output_ph):
            out_ph.add(i)
        after = len(read_calls) + len(write_calls) + len(store_calls) + len(in_calls) \
            + len(out_calls)
        if after > before:
            days[c.ts[:10]] += 1
            sessions.add(c.session)

    frows = []
    for f in sorted(files.values(), key=lambda f: (-(f["reads"] + f["writes"]), f["path"])):
        frows.append({"path": f["path"], "reads": f["reads"], "writes": f["writes"],
                      "tools": dict(sorted(f["tools"].items())),
                      "sessions": len(f["sessions"] - {None}),
                      "first_day": f["first_day"], "last_day": f["last_day"]})
    krows = [{"kind": k, "input_calls": len(v["input"]), "output_calls": len(v["output"]),
              "output_placeholder_calls": len(v["placeholder"])}
             for k, v in sorted(kinds.items(), key=lambda kv: (-len(kv[1]["output"]), kv[0]))]
    rotate = [f["path"] for f in frows if f["reads"]][:10]
    rotate_kinds = [ROTATE.get(k["kind"], k["kind"]) for k in krows
                    if k["output_calls"] - k["output_placeholder_calls"] > 0
                    or k["input_calls"] > 0]
    all_days = sorted({c.ts[:10] for c in res.calls})
    return {
        "source": {"agent": "Claude Code", "files": res.files,
                   "subagents_included": res.include_subagents,
                   "first_day": all_days[0] if all_days else None,
                   "last_day": all_days[-1] if all_days else None, "clock": "UTC"},
        "totals": {"tool_calls": len(res.calls), "read_file_calls": len(read_calls),
                   "write_file_calls": len(write_calls), "store_or_env_calls": len(store_calls),
                   "input_value_calls": len(in_calls), "input_placeholder_calls": len(in_ph),
                   "output_value_calls": len(out_calls), "output_placeholder_calls": len(out_ph),
                   "days_with_a_touch": len(days), "sessions_with_a_touch": len(sessions - {None})},
        "files": frows,
        "stores": dict(sorted(stores.items(), key=lambda kv: (-kv[1], kv[0]))),
        "values": krows,
        "rotate_first": {"files": rotate, "kinds": rotate_kinds},
    }


def render(s: dict, header: str, fmt: str = "table") -> str:
    from .allowsuggest import _table
    if fmt == "json":
        return json.dumps(dict(s, privacy=header.split(" | ", 1)[-1]), indent=2, sort_keys=True)
    if fmt == "tsv":
        out = ["section\tkey\tvalue"]
        out += ["totals\t%s\t%s" % kv for kv in s["totals"].items()]
        out += ["file\t%s\t%d\t%d" % (f["path"], f["reads"], f["writes"]) for f in s["files"]]
        out += ["store\t%s\t%d" % kv for kv in s["stores"].items()]
        out += ["value\t%s\t%d\t%d\t%d" % (k["kind"], k["input_calls"], k["output_calls"],
                                          k["output_placeholder_calls"]) for k in s["values"]]
        return "\n".join(out)
    t, src = s["totals"], s["source"]
    lines = [header,
             "secret-touch: past tool calls that read or printed secret-shaped files or values. "
             "Values are never printed.", "",
             "Source: Claude Code transcripts, %d files, %s to %s (UTC), subagents %s" % (
                 src["files"], src["first_day"], src["last_day"],
                 "included" if src["subagents_included"] else "not included"), "",
             "Totals  [calls]"]
    lines += _table([
        ["tool calls scanned", t["tool_calls"]],
        ["read a secret-shaped file (Read, Grep, Bash cat/grep/source/cp, < redirect ...)",
         t["read_file_calls"]],
        ["wrote a secret-shaped file (Edit, Write, Bash > redirect)", t["write_file_calls"]],
        ["read a secret store or dumped the environment", t["store_or_env_calls"]],
        ["secret-shaped value in the call input (command or file text)",
         "%d  (placeholder-like only: %d)" % (t["input_value_calls"], t["input_placeholder_calls"])],
        ["secret-shaped value in the tool output",
         "%d  (placeholder-like only: %d)" % (t["output_value_calls"],
                                              t["output_placeholder_calls"])],
        ["UTC days / sessions with one of these", "%d / %d" % (t["days_with_a_touch"],
                                                              t["sessions_with_a_touch"])]])
    lines += ["", "Secret-shaped files  [path label, reads, writes, tools, sessions, first day, "
                  "last day]"]
    lines += _table([[f["path"], f["reads"], f["writes"],
                      ", ".join("%s %d" % kv for kv in f["tools"].items()), f["sessions"],
                      f["first_day"], f["last_day"]] for f in s["files"]])
    lines += ["", "Secret stores and environment  [kind, calls]"]
    lines += _table([[k, v] for k, v in s["stores"].items()])
    lines += ["", "Secret-shaped values  [kind, calls with it in the input, in the output, "
                  "output placeholder-like]"]
    lines += _table([[k["kind"], k["input_calls"], k["output_calls"],
                      k["output_placeholder_calls"]] for k in s["values"]])
    r = s["rotate_first"]
    lines += ["", "Rotate first (if these transcripts or an agent tool that saw them were exposed):"]
    lines += ["  files:  " + (", ".join(r["files"]) if r["files"] else "(none)"),
              "  values: " + (", ".join(r["kinds"]) if r["kinds"] else "(none)")]
    lines += [
        "",
        "Notes:",
        "  - Tool output goes into the model context, and the transcripts under",
        "    ~/.claude/projects keep it in clear text. A value counted here is on this disk.",
        "  - A name or form match is not proof of a live secret. Placeholder-like values",
        "    (EXAMPLE, xxxx, 1234567890, test, fake) are counted apart.",
        "  - Not seen: files read inside scripts, paths built from variables other than",
        "    $HOME, and values in other forms. Heredoc bodies are not file arguments.",
    ]
    return "\n".join(lines)
