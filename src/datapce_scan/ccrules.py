"""Claude Code permission rules as written in settings files: parse, match, split.

Source of the semantics (read 2026-10-23): https://code.claude.com/docs/en/permissions
  - "Wildcard patterns": `*` matches any text, also spaces; a trailing " *" (the only `*`)
    also matches the bare command; `:*` at the end is the same as " *"; `Bash(*)` == `Bash`.
  - "Compound commands": an allow rule must match each subcommand; separators && || ; | |& &
    and newlines; a dangling && or || makes the command unparseable.
  - "Wrappers": timeout, time, nice, nohup, stdbuf, command, builtin, noglob and bare xargs
    are stripped before matching. sudo, env and xargs with flags are not.
  - "Read-only commands": a built-in set runs with no prompt. The docs name ls, cat, echo,
    pwd, head, tail, grep, find, wc, which, diff, stat, du, cd and read-only forms of git. The
    full set is not published; READ_ONLY below is the named part only.
  - "Wildcard patterns": the words before the first `*` match as written, so quoting counts
    (`git 'push'` is not `git push`). Allow rules do not match past a leading assignment,
    except known-safe variables (the docs name NODE_ENV only; SAFE_ENV).
  - "Exec wrappers and find actions": a rule with `*` cannot approve watch, setsid, ionice,
    flock, or find with -exec, -delete, -fprint ... ; an exact rule can.
  - "Tool name wildcards": allow globs need a literal `mcp__<server>__` prefix; others are
    skipped. An `mcp__` rule with parentheses is skipped.
  - "Read and Edit": Edit rules cover all file-editing tools; Read rules (best effort) cover
    Grep and Glob; Write(path), NotebookEdit(path), Glob(path), MultiEdit(path) never match.
    `//p` absolute, `~/p` home, `/p` the settings source (anchor), `p` and `./p` the current
    directory; a pattern with no inner slash matches at any depth under it (gitignore).
  - "WebFetch": `domain:*` matches all; a leading `*.` any subdomain depth; any other `*`
    one label only; case and a trailing dot are ignored.

Known gaps (printed by the commands): the full known-safe variable list is not published;
the anchor of `/p` rules in managed settings is not documented (the working directory is
used); a $( ) substitution is matched as a placeholder word.

This module only reads and matches. It never writes a settings file.

Python 3.9+, stdlib only.
"""
import fnmatch
import os
import re
from urllib.parse import urlsplit
from typing import Dict, List, NamedTuple, Optional, Tuple

from . import shellparse

_RULE_RE = re.compile(r"^([A-Za-z0-9_*.-]+)(?:\((.*)\))?$", re.S)

# Documented wrappers that Claude Code strips before it matches a Bash rule.
_CC_WRAPPERS = {"timeout", "time", "nice", "nohup", "stdbuf", "command", "builtin", "noglob"}
_WRAPPER_ARG = {"timeout": {"-s", "-k", "--signal", "--kill-after"}, "nice": {"-n"},
                "stdbuf": {"-i", "-o", "-e"}}

READ_ONLY = {"ls", "cat", "echo", "pwd", "head", "tail", "grep", "find", "wc", "which", "diff",
             "stat", "du", "cd"}
GIT_READ_ONLY = {"status", "log", "diff", "show", "rev-parse", "ls-files", "blame"}
_FIND_ACTIONS = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0",
                 "-fprintf", "-fls", "-files0-from", "-rm"}
EXEC_WRAPPERS = {"watch", "setsid", "ionice", "flock"}
# docs "Read-only commands": a command that sets, unsets or loops over certain special shell
# variables, such as PATH or IFS, prompts. The docs name these two only.
SPECIAL_VARS = {"PATH", "IFS"}
_VAR_BUILTINS = {"export", "unset", "declare", "local", "readonly", "typeset", "read"}
SAFE_ENV = {"NODE_ENV"}
EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
READ_TOOLS = {"Read", "Grep", "Glob"}
NEVER_PATH_TOOLS = {"Write", "NotebookEdit", "Glob", "MultiEdit"}
_PUNCT = set("();<>|&")
_SPACE = set(" \t\r\n")


def parse_rule(rule: str) -> Optional[Tuple[str, Optional[str]]]:
    """'Bash(npm test:*)' -> ('Bash', 'npm test *'). 'Bash' and 'Bash(*)' -> ('Bash', None)."""
    if not isinstance(rule, str):
        return None
    m = _RULE_RE.match(rule.strip())
    if not m:
        return None
    tool, spec = m.group(1), m.group(2)
    if spec is None or spec.strip() in ("", "*"):
        return tool, None
    if tool in ("Bash", "PowerShell") and spec.endswith(":*"):
        spec = spec[:-2].rstrip() + " *"
    return tool, spec


def _star_match(spec: str, text: str) -> bool:
    """`*` (any text, also spaces) glob match in linear time: the first part is a prefix, the
    last a suffix, the middle parts are found left to right (fix round 2, M2)."""
    parts = spec.split("*")
    first, last = parts[0], parts[-1]
    if not text.startswith(first) or not text.endswith(last):
        return False
    pos, end = len(first), len(text) - len(last)
    if end < pos:
        return False
    for p in parts[1:-1]:
        k = text.find(p, pos, end)
        if k < 0:
            return False
        pos = k + len(p)
    return True


def bash_spec_matches(spec: Optional[str], command: str) -> bool:
    """Does one Bash rule specifier match one subcommand text? None means every command."""
    if spec is None:
        return True
    if "*" not in spec:
        return command == spec
    if spec.count("*") == 1 and spec.endswith(" *"):
        head = spec[:-2]  # a trailing " *" also matches the bare command
        return command == head or command.startswith(head + " ")
    return _star_match(spec, command)


class Sub(NamedTuple):
    argv: List[str]
    assigns: Dict[str, str]
    depth: int
    raw: Optional[List[str]] = None  # the words as written (quotes kept), same length as argv
    redirects: Tuple[Tuple[str, str], ...] = ()  # (operator, target) pairs

    @property
    def text(self) -> str:
        return " ".join(self.argv)

    @property
    def written(self) -> str:
        return " ".join(self.raw) if self.raw is not None else self.text


def _raw_tokens(clean: str) -> Optional[List[Tuple[str, str]]]:
    """(value, as written) per shell word or operator group, like shlex posix with
    punctuation_chars. None if a quote does not close."""
    out, i, n = [], 0, len(clean)
    while i < n:
        ch = clean[i]
        if ch in _SPACE:
            i += 1
            continue
        if ch in _PUNCT:
            j = i
            while j < n and clean[j] in _PUNCT:
                j += 1
            out.append((clean[i:j], clean[i:j]))
            i = j
            continue
        j, val = i, []
        while j < n and clean[j] not in _SPACE and clean[j] not in _PUNCT:
            c = clean[j]
            if c == "'":
                k = clean.find("'", j + 1)
                if k < 0:
                    return None
                val.append(clean[j + 1:k])
                j = k + 1
            elif c == '"':
                k, buf = j + 1, []
                while k < n and clean[k] != '"':
                    if clean[k] == "\\" and k + 1 < n and clean[k + 1] in '"\\':
                        buf.append(clean[k + 1])
                        k += 2
                    else:
                        buf.append(clean[k])
                        k += 1
                if k >= n:
                    return None
                val.append("".join(buf))
                j = k + 1
            elif c == "\\":
                if j + 1 < n:
                    val.append(clean[j + 1])
                j += 2
            else:
                val.append(c)
                j += 1
        out.append(("".join(val), clean[i:j]))
        i = j
    return out


def _is_op_word(v: str, r: str) -> bool:
    return v == r and bool(v) and all(c in "();&|" for c in v)


def _is_redir_word(v: str, r: str) -> bool:
    return v == r and bool(v) and all(c in "<>&|" for c in v) and ("<" in v or ">" in v)


def _segments_raw(pairs: List[Tuple[str, str]]):
    """Segments of (value, raw) pairs, each with its (operator, target) redirects."""
    segs, cur, red, i = [], [], [], 0
    while i < len(pairs):
        v, r = pairs[i]
        if _is_redir_word(v, r):
            if i + 1 < len(pairs) and not _is_op_word(*pairs[i + 1]) \
                    and not _is_redir_word(*pairs[i + 1]):
                red.append((v, pairs[i + 1][0]))
                i += 2
            else:
                i += 1
            continue
        if _is_op_word(v, r):
            if cur or red:  # a redirect after a closer such as `)` is kept (fix round 2, I4)
                segs.append((cur, tuple(red)))
            cur, red = [], []
            i += 1
            continue
        cur.append((v, r))
        i += 1
    if cur or red:
        segs.append((cur, tuple(red)))
    return segs


def _cc_unwrap(argv: List[str]) -> List[str]:
    for _ in range(8):
        if not argv:
            return argv
        w = argv[0]
        if w == "xargs" and len(argv) > 1 and not argv[1].startswith("-"):
            argv = argv[1:]
            continue
        if w not in _CC_WRAPPERS:
            return argv
        if w == "command" and len(argv) > 1 and argv[1] in ("-v", "-V"):
            return argv
        rest, i, with_arg = argv[1:], 0, _WRAPPER_ARG.get(w, set())
        while i < len(rest) and rest[i].startswith("-") and rest[i] != "-":
            i += 2 if rest[i] in with_arg else 1
        rest = rest[i:]
        if w == "timeout" and rest:
            rest = rest[1:]  # the duration
        if not rest:
            return argv
        argv = rest
    return argv


def subcommands(text: str, _depth: int = 0) -> Optional[List[Sub]]:
    """Split a Bash command the way Claude Code matches allow rules. None = unparseable."""
    if _depth > shellparse.MAX_DEPTH:
        return []
    clean, subs = shellparse.prepass(text or "")
    tokens, fallback = shellparse._tokens(clean)
    if fallback:
        return None
    if tokens and tokens[-1] in ("&&", "||", "|", "|&"):
        return None
    pairs = _raw_tokens(clean)
    if pairs is None or [v for v, _ in pairs] != tokens:
        pairs = [(t, t) for t in tokens]  # fall back: match the unquoted words
    out: List[Sub] = []
    nested: List[int] = []
    for seg, red in _segments_raw(pairs):
        while seg and seg[0][0] in shellparse.KEYWORDS_LEAD:
            seg = seg[1:]
        if not seg or seg[0][0] in shellparse.KEYWORDS_SKIP:
            if len(seg) > 1 and seg[0][0] in ("for", "select") and seg[1][0] in SPECIAL_VARS:
                out.append(Sub([seg[0][0], seg[1][0]], {}, _depth, None, red))
            elif red:
                # a redirect on a compound command (done > f, } < f, fi > f, ) > f): an empty
                # subcommand that holds it, so writes and reads of the target still count
                out.append(Sub([], {}, _depth, [], red))
            continue
        assigns: Dict[str, str] = {}
        while seg and shellparse._ASSIGN_RE.match(seg[0][0]):
            m = shellparse._ASSIGN_RE.match(seg[0][0])
            assigns[m.group(1)] = m.group(2)
            seg = seg[1:]
        words = [v for v, _ in seg]
        for w in list(assigns.values()) + words:
            nested.extend(int(k) for k in shellparse._PLACEHOLDER_RE.findall(w))
        if not seg:
            continue
        argv = _cc_unwrap(words)
        raw = [r for _, r in seg][len(words) - len(argv):]
        out.append(Sub(argv, assigns, _depth, raw, red))
    for k in nested:
        if k < len(subs):
            inner = subcommands(subs[k], _depth + 1)
            if inner is None:
                return None
            out.extend(inner)
    return out


def no_op_redirect(op: str, target: str) -> bool:
    """A redirect that touches no file: the target is /dev/null, or the op is an fd copy or
    close (>& or <&; the parser drops the N of N>& and N<&) with an all-digit or - target, as
    in >&2, 2>&1, >&-, <&3. Bash writes a file for every other output redirect: >&file and
    &>file write stdout and stderr to file; > 5 and > - write files named 5 and -."""
    if target == "/dev/null":
        return True
    return op in (">&", "<&") and (target == "-" or (target.isascii() and target.isdigit()))


def writes_file(sub: Sub) -> bool:
    """An output redirect to a file (see no_op_redirect)."""
    return any(">" in op and not no_op_redirect(op, target) for op, target in sub.redirects)


def writes_special(sub: Sub) -> bool:
    """Sets, unsets or loops over PATH or IFS."""
    if any(k in SPECIAL_VARS for k in sub.assigns):
        return True
    if not sub.argv:
        return False
    if sub.argv[0] in ("for", "select"):
        return len(sub.argv) > 1 and sub.argv[1] in SPECIAL_VARS
    if sub.argv[0] in _VAR_BUILTINS:
        return any(a.split("=", 1)[0].lstrip("+") in SPECIAL_VARS for a in sub.argv[1:])
    return False


def sub_read_only(sub: Sub) -> bool:
    """is_read_only on the words, and no output redirect to a file, and no PATH/IFS write."""
    return is_read_only(sub.argv) and not writes_file(sub) and not writes_special(sub)


def is_read_only(argv: List[str]) -> bool:
    """The named part of Claude Code's built-in read-only set (see module docstring)."""
    if not argv:
        return True
    prog = argv[0]
    if prog == "git":
        rest = argv[1:]
        return bool(rest) and rest[0] in GIT_READ_ONLY
    if prog not in READ_ONLY:
        return False
    if prog == "find":
        return not any(a in _FIND_ACTIONS for a in argv[1:])
    return True


# ---------------------------------------------------------------- one rule on one past call

def no_prefix_approval(argv: List[str]) -> bool:
    """Commands that a rule with `*` cannot approve (exec wrappers, find actions)."""
    if not argv:
        return False
    if argv[0] in EXEC_WRAPPERS:
        return True
    return argv[0] == "find" and any(a in _FIND_ACTIONS for a in argv[1:])


def blocks_allow(sub: Sub) -> bool:
    """A leading assignment that an allow rule does not match past."""
    return any(k not in SAFE_ENV for k in sub.assigns)


def allow_matches(spec: Optional[str], sub: Sub) -> bool:
    """Does one Bash allow-rule specifier approve one subcommand, as the docs describe?"""
    if spec is None:
        return True
    if blocks_allow(sub):
        return False
    if "*" in spec and no_prefix_approval(sub.argv):
        return False
    return bash_spec_matches(spec, sub.written)


def allow_glob_skipped(rtool: str) -> bool:
    """An allow rule with a tool-name glob that is not after a literal mcp__<server>__."""
    g = min([i for i in (rtool.find("*"), rtool.find("?"), rtool.find("[")) if i >= 0],
            default=-1)
    if g < 0:
        return False
    head = rtool[:g]
    return not (head.startswith("mcp__") and "__" in head[5:] and head.index("__", 5) > 5)


def domain_matches(dom: str, host: str) -> bool:
    dom, host = dom.lower().rstrip("."), host.lower().rstrip(".")
    if dom == "*":
        return True
    lead = ""
    if dom.startswith("*."):
        lead, dom = r"(?:[^.]+\.)+", dom[2:]
    rx = "^" + lead + re.escape(dom).replace(r"\*", "[^.]*") + "$"
    return bool(re.match(rx, host))


def call_matches(rule: str, tool: str, command: Optional[str], target: Optional[str],
                 cwd: Optional[str] = None, home: Optional[str] = None,
                 anchor: Optional[str] = None) -> List[str]:
    """The parts of one past call that one allow rule matches: Bash subcommand texts, or
    [tool] for any other tool. An empty list means no match. anchor is the directory that a
    `/path` rule anchors at (settings source); None means the working directory."""
    pr = parse_rule(rule)
    if pr is None:
        return []
    rtool, spec = pr
    if allow_glob_skipped(rtool):
        return []
    if rtool.startswith("mcp__"):
        if "(" in rule:
            return []
        if "*" in rtool:
            return [tool] if fnmatch.fnmatchcase(tool, rtool) else []
        return [tool] if tool == rtool or tool.startswith(rtool + "__") else []
    if rtool == "Edit":
        same = tool in EDIT_TOOLS
    elif rtool == "Read":
        same = tool in READ_TOOLS
    else:
        same = rtool == tool
    if not same:
        return []
    if tool == "Bash":
        if command is None:
            return [] if spec is not None else ["(no command text)"]
        subs = subcommands(command)
        if subs is None:
            return [command] if spec is None else []
        return [s.text for s in subs if allow_matches(spec, s)]
    if spec is None:
        return [tool]
    if rtool in NEVER_PATH_TOOLS:
        return []
    if tool == "WebFetch":
        if not spec.startswith("domain:") or not target:
            return []
        try:
            host = urlsplit(target if "://" in target else "//" + target).hostname or ""
        except ValueError:
            return []
        return [tool] if domain_matches(spec[len("domain:"):], host) else []
    if target and path_matches(spec, target, cwd, home, anchor):
        return [tool]
    return []


def path_matches(spec: str, path: str, cwd: Optional[str] = None,
                 home: Optional[str] = None, anchor: Optional[str] = None) -> bool:
    """The gitignore-style Read/Edit patterns of an allow rule: //p absolute, ~/p home, /p at
    the settings source (anchor, else cwd), p and ./p at the current directory; a pattern with
    no inner slash matches at any depth under it. ** crosses directories, * does not. With no
    cwd a bare pattern matches at any depth (no anchor is known)."""
    home = home or os.path.expanduser("~")
    if spec.startswith("//"):
        pat = spec[1:]
    elif spec.startswith("~/"):
        pat = home.rstrip("/") + spec[1:]
    elif spec.startswith("/"):
        base = anchor or cwd
        if not base:
            return False
        pat = base.rstrip("/") + spec
    elif spec.startswith("./"):
        if not cwd:
            return False
        pat = cwd.rstrip("/") + "/" + spec[2:]
    elif not cwd:
        pat = "**/" + spec
    else:
        anywhere = "/" not in spec.rstrip("/")
        pat = cwd.rstrip("/") + "/" + ("**/" if anywhere else "") + spec
    if not path.startswith("/") and cwd:
        path = os.path.normpath(os.path.join(cwd, path))
    if pat.endswith("/**") and path == pat[:-3]:
        return True
    return _glob_match(pat, path)


_LIT, _ONE, _STAR, _ANY, _DIRS = range(5)


def _glob_tokens(pat: str) -> List[Tuple[int, str]]:
    """Tokens in the order the docs' gitignore forms apply: `**/` first (leftmost, no
    overlap), then `**`, then `*` and `?`."""
    out: List[Tuple[int, str]] = []
    for k, seg in enumerate(pat.split("**/")):
        if k:
            out.append((_DIRS, ""))  # zero or more directories: (?:.*/)?
        for j, part in enumerate(seg.split("**")):
            if j:
                out.append((_ANY, ""))  # any text, also /
            for ch in part:
                out.append((_STAR, "") if ch == "*" else (_ONE, "") if ch == "?"
                           else (_LIT, ch))
    return out


def _glob_match(pat: str, path: str) -> bool:
    """gitignore-style glob (*, **, **/, ?) as a state set, one pass over the path: time is
    len(path) x len(pattern), no backtracking (fix round 2, M2)."""
    toks = _glob_tokens(pat)
    n = len(toks)

    def close(states):
        stack, seen = list(states), set(states)
        while stack:
            st = stack.pop()
            if st < n and toks[st][0] in (_STAR, _ANY, _DIRS) and st + 1 not in seen:
                seen.add(st + 1)
                stack.append(st + 1)
        return seen

    cur = close({0})
    for ch in path:
        nxt = set()
        for st in cur:
            if st > n:  # inside the .* of a **/ token: st = n + 1 + token index
                k = st - n - 1
                nxt.add(st)
                if ch == "/":
                    nxt.add(k + 1)
                continue
            if st == n:
                continue
            kind, c = toks[st]
            if kind == _LIT:
                if ch == c:
                    nxt.add(st + 1)
            elif kind == _ONE:
                if ch != "/":
                    nxt.add(st + 1)
            elif kind == _STAR:
                if ch != "/":
                    nxt.add(st)
            elif kind == _ANY:
                nxt.add(st)
            else:  # _DIRS
                nxt.add(n + 1 + st)
                if ch == "/":
                    nxt.add(st + 1)
        if not nxt:
            return False
        cur = close(nxt)
    return n in cur
