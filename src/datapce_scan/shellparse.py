"""Split a Bash command string into simple commands, with a real shell tokenizer (shlex).

The parser is for counting and rule matching. It does not run or expand anything.

Steps:
1. A quote-aware pre-pass removes heredoc bodies, comments and line continuations, turns
   unquoted newlines into ';', and cuts out $( ), backtick and <( ) substitutions. Each
   substitution becomes a placeholder word and is parsed again as a nested command.
2. shlex (posix, punctuation_chars) splits the rest into words and operators.
3. Operators split simple commands. Redirections and their targets are dropped. Leading
   NAME=value words become assignments. Wrappers (sudo, env, nohup, timeout, xargs, ...) are
   removed. `bash -c`, `sh -c`, `eval` and `find -exec` give nested commands.

Python 3.9+, stdlib only.
"""
import os
import re
import shlex
from typing import Dict, List, Optional, Tuple

MAX_DEPTH = 4
PLACEHOLDER = "__DPS%d__"
_PLACEHOLDER_RE = re.compile(r"__DPS(\d+)__")
_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\+?=(.*)$", re.S)
_OPCHARS = set("();&|")
_REDIR_CHARS = set("<>&|")
_WORD_BREAK = set(" \t\n;&|()<>")

SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "ash", "fish", "mksh"}
KEYWORDS_LEAD = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}"}
KEYWORDS_SKIP = {"fi", "done", "esac", "for", "select", "case", "function", "in", "}"}
DECLARE = {"export", "local", "declare", "readonly", "typeset"}


class SimpleCommand:
    __slots__ = ("argv", "assigns", "depth", "fallback")

    def __init__(self, argv: List[str], assigns: Dict[str, str], depth: int, fallback: bool):
        self.argv = argv
        self.assigns = assigns
        self.depth = depth
        self.fallback = fallback

    @property
    def text(self) -> str:
        return " ".join(shlex.quote(a) for a in self.argv)

    def __repr__(self) -> str:
        return "SimpleCommand(%r, depth=%d)" % (self.argv, self.depth)


class Parsed(list):
    """A list of SimpleCommand, plus names of variables set from mktemp in the same text."""

    def __init__(self):
        super().__init__()
        self.temp_vars = set()
        self.vars: Dict[str, Optional[str]] = {}
        self.fallback = False


# ---------------------------------------------------------------- pre-pass

def _match_paren(text: str, i: int) -> int:
    """text[i] is just after an opening '('. Return the index of the matching ')', or len."""
    depth, n, q = 1, len(text), None
    while i < n:
        ch = text[i]
        if q == "'":
            if ch == "'":
                q = None
        elif ch == "\\":
            i += 1
        elif q == '"':
            if ch == '"':
                q = None
        elif ch in "'\"":
            q = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def _match_backtick(text: str, i: int) -> int:
    n = len(text)
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "`":
            return i
        i += 1
    return n


def _read_heredoc_word(text: str, i: int) -> Tuple[str, int]:
    n = len(text)
    while i < n and text[i] in " \t":
        i += 1
    word = []
    while i < n and text[i] not in " \t\n;&|()<>":
        ch = text[i]
        if ch in "'\"":
            j = text.find(ch, i + 1)
            j = n if j < 0 else j
            word.append(text[i + 1:j])
            i = j + 1
            continue
        if ch == "\\":
            i += 1
            if i < n:
                word.append(text[i])
            i += 1
            continue
        word.append(ch)
        i += 1
    return "".join(word), i


def _skip_heredoc_bodies(text: str, i: int, pending: List[Tuple[str, bool]]) -> int:
    """i is just after a newline. Skip the body lines of each pending heredoc."""
    n = len(text)
    for delim, strip_tabs in pending:
        while i < n:
            j = text.find("\n", i)
            line = text[i:] if j < 0 else text[i:j]
            i = n if j < 0 else j + 1
            if (line.lstrip("\t") if strip_tabs else line) == delim:
                break
    pending.clear()
    return i


def prepass(text: str) -> Tuple[str, List[str]]:
    out: List[str] = []
    subs: List[str] = []
    pending: List[Tuple[str, bool]] = []
    q: Optional[str] = None
    i, n = 0, len(text)

    def word_start() -> bool:
        return not out or out[-1][-1:] in _WORD_BREAK

    def add_sub(inner: str) -> None:
        subs.append(inner)
        out.append(PLACEHOLDER % (len(subs) - 1))

    while i < n:
        ch = text[i]
        if q == "'":
            out.append(ch)
            if ch == "'":
                q = None
            i += 1
            continue
        if ch == "\\":
            if text.startswith("\\\n", i):
                i += 2
                continue
            out.append(text[i:i + 2])
            i += 2
            continue
        if ch == "$" and text.startswith("$((", i):
            j = _match_paren(text, i + 2)
            out.append("0")
            i = (j + 2) if text.startswith("))", j) else j + 1
            continue
        if ch == "$" and text.startswith("$(", i):
            j = _match_paren(text, i + 2)
            add_sub(text[i + 2:j])
            i = j + 1
            continue
        if ch == "`":
            j = _match_backtick(text, i + 1)
            add_sub(text[i + 1:j])
            i = j + 1
            continue
        if q == '"':
            out.append(ch)
            if ch == '"':
                q = None
            i += 1
            continue
        # unquoted
        if ch in "'\"":
            q = ch
            out.append(ch)
            i += 1
            continue
        if ch in "<>" and text.startswith("(", i + 1):  # process substitution
            j = _match_paren(text, i + 2)
            out.append(" ")
            add_sub(text[i + 2:j])
            i = j + 1
            continue
        if ch == "#" and word_start():
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if ch == "\n":
            out.append(" ; ")
            i += 1
            if pending:
                i = _skip_heredoc_bodies(text, i, pending)
            continue
        if text.startswith("<<<", i):
            out.append(" <<< ")
            i += 3
            continue
        if text.startswith("<<", i):
            j = i + 2
            strip_tabs = text.startswith("-", j)
            if strip_tabs:
                j += 1
            delim, j = _read_heredoc_word(text, j)
            if delim:
                pending.append((delim, strip_tabs))
            out.append(" ")
            i = j
            continue
        if ch.isdigit() and word_start():
            m = re.match(r"\d+(?=[<>])", text[i:])
            if m:
                i += m.end()
                continue
        out.append(ch)
        i += 1
    return "".join(out), subs


# ---------------------------------------------------------------- tokens and segments

def _tokens(clean: str) -> Tuple[List[str], bool]:
    lex = shlex.shlex(clean, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        return list(lex), False
    except ValueError:
        toks = re.findall(r"&&|\|\||[;&|()]|[<>]+&?|[^\s;&|()<>]+", clean)
        return toks, True


def _is_op(tok: str) -> bool:
    return bool(tok) and all(c in _OPCHARS for c in tok)


def _is_redir(tok: str) -> bool:
    return bool(tok) and all(c in _REDIR_CHARS for c in tok) and ("<" in tok or ">" in tok)


def _segments(tokens: List[str]) -> List[List[str]]:
    segs, cur, skip_next = [], [], False
    for tok in tokens:
        if skip_next:
            skip_next = False
            if not _is_op(tok):
                continue
        if _is_redir(tok):
            skip_next = True
            continue
        if _is_op(tok):
            if cur:
                segs.append(cur)
            cur = []
            continue
        cur.append(tok)
    if cur:
        segs.append(cur)
    return segs


# ---------------------------------------------------------------- wrappers

_SUDO_ARG = {"-u", "-g", "-U", "-C", "-p", "-r", "-t", "-D", "-R", "-T", "-h"}
_XARGS_ARG = {"-I", "-n", "-P", "-L", "-d", "-s", "-E", "-a", "-J", "-R", "-S"}
_TIMEOUT_ARG = {"-s", "-k", "--signal", "--kill-after"}


def _skip_opts(args: List[str], with_arg: set) -> List[str]:
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return args[i + 1:]
        if not a.startswith("-") or a == "-":
            break
        i += 2 if a in with_arg else 1
    return args[i:]


def unwrap(argv: List[str]) -> List[str]:
    for _ in range(8):
        if not argv:
            return argv
        base = os.path.basename(argv[0])
        rest = argv[1:]
        if base in ("sudo", "doas"):
            new = _skip_opts(rest, _SUDO_ARG)
        elif base == "env":
            new = _skip_opts(rest, {"-u", "-C", "-P", "-S"})
            while new and _ASSIGN_RE.match(new[0]):
                new = new[1:]
        elif base in ("nohup", "builtin", "caffeinate", "stdbuf"):
            new = _skip_opts(rest, set())
        elif base == "exec":
            new = _skip_opts(rest, {"-a"})
        elif base == "command":
            if any(a in ("-v", "-V") for a in rest[:2]):
                return argv
            new = _skip_opts(rest, set())
        elif base == "time":
            new = _skip_opts(rest, set())
        elif base == "nice":
            new = _skip_opts(rest, {"-n"})
        elif base in ("timeout", "gtimeout"):
            new = _skip_opts(rest, _TIMEOUT_ARG)
            new = new[1:] if new else new
        elif base == "xargs":
            new = _skip_opts(rest, _XARGS_ARG)
        else:
            return argv
        if not new:
            return argv
        argv = new
    return argv


def _shell_script(argv: List[str]) -> Optional[str]:
    """Return the -c script of a shell call, else None."""
    if os.path.basename(argv[0]) not in SHELLS:
        return None
    found, i = False, 1
    while i < len(argv):
        a = argv[i]
        if a == "--":
            i += 1
            break
        if a in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file"):
            i += 2
            continue
        if a.startswith("-") and len(a) > 1:
            if not a.startswith("--") and "c" in a[1:]:
                found = True
            i += 1
            continue
        break
    if found and i < len(argv):
        return argv[i]
    return None


def _find_exec(argv: List[str]) -> List[List[str]]:
    out = []
    if os.path.basename(argv[0]) != "find":
        return out
    i = 0
    while i < len(argv):
        if argv[i] in ("-exec", "-execdir", "-ok", "-okdir"):
            j = i + 1
            while j < len(argv) and argv[j] not in (";", "+", "\\;"):
                j += 1
            if j > i + 1:
                out.append(argv[i + 1:j])
            i = j
        i += 1
    return out


# ---------------------------------------------------------------- parse

def parse(text: str, max_depth: int = MAX_DEPTH) -> Parsed:
    result = Parsed()
    _parse_into(text or "", 0, max_depth, result)
    return result


def _parse_into(text: str, depth: int, max_depth: int, result: Parsed) -> None:
    clean, subs = prepass(text)
    tokens, fallback = _tokens(clean)
    if fallback:
        result.fallback = True

    def nested_from_words(words: List[str]) -> None:
        if depth + 1 > max_depth:
            return
        for w in words:
            for m in _PLACEHOLDER_RE.finditer(w):
                k = int(m.group(1))
                if k < len(subs):
                    _parse_into(subs[k], depth + 1, max_depth, result)

    for seg in _segments(tokens):
        while seg and seg[0] in KEYWORDS_LEAD:
            seg = seg[1:]
        if not seg or seg[0] in KEYWORDS_SKIP:
            continue
        assigns: Dict[str, str] = {}
        while seg and _ASSIGN_RE.match(seg[0]):
            m = _ASSIGN_RE.match(seg[0])
            assigns[m.group(1)] = m.group(2)
            seg = seg[1:]
        if seg and seg[0] in DECLARE:
            for a in seg[1:]:
                m = _ASSIGN_RE.match(a)
                if m:
                    assigns[m.group(1)] = m.group(2)
        for name, val in assigns.items():
            m = _PLACEHOLDER_RE.match(val.strip())
            if m and int(m.group(1)) < len(subs):
                inner = subs[int(m.group(1))].strip().split()
                if inner and os.path.basename(inner[0]) == "mktemp":
                    result.temp_vars.add(name)
            literal = not ("$" in val or "`" in val or _PLACEHOLDER_RE.search(val))
            result.vars[name] = val if literal else None
        nested_from_words(list(assigns.values()))
        if not seg:
            continue
        argv = unwrap(seg)
        nested_from_words(argv)
        result.append(SimpleCommand(argv, assigns, depth, fallback))
        _nested_from_argv(argv, depth, max_depth, result)


def _nested_from_argv(argv: List[str], depth: int, max_depth: int, result: Parsed) -> None:
    if depth + 1 > max_depth or not argv:
        return
    script = _shell_script(argv)
    if script is not None:
        _parse_into(script, depth + 1, max_depth, result)
        return
    if os.path.basename(argv[0]) == "eval" and len(argv) > 1:
        _parse_into(" ".join(argv[1:]), depth + 1, max_depth, result)
        return
    for inner in _find_exec(argv):
        inner = unwrap(inner)
        result.append(SimpleCommand(inner, {}, depth + 1, False))
        _nested_from_argv(inner, depth + 1, max_depth, result)


_HEREDOC_OP = re.compile(r"(?<!<)<<(?!<)(-?)\s*(['\"]?)([A-Za-z0-9_.-]+)\2")


def heredoc_free(text: str) -> str:
    """The text without heredoc body lines (a line-based, quote-blind cut)."""
    out, pending = [], []
    for line in (text or "").split("\n"):
        if pending:
            delim, strip_tabs = pending[0]
            if (line.lstrip("\t") if strip_tabs else line) == delim:
                pending.pop(0)
            continue
        out.append(line)
        for m in _HEREDOC_OP.finditer(line):
            pending.append((m.group(3), m.group(1) == "-"))
    return "\n".join(out)


def temp_vars(text: str) -> set:
    return parse(text).temp_vars


def family(argv: List[str]) -> str:
    """Command family: the basename of the first word."""
    if not argv:
        return "(none)"
    w = argv[0]
    if _PLACEHOLDER_RE.search(w):
        return "(substitution)"
    if w.startswith("$"):
        return "(variable)"
    base = os.path.basename(w.rstrip("/")) or w
    return base
