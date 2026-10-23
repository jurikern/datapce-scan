"""Rule sets as data, and the matchers that apply them to one past Bash call.

Rule set file (JSON): {"name", "source_url", "licence", "fetched", "reuse", ..., "rules": [...]}.
Rule: {"name", "action": "deny"|"ask", "match": {"kind": ...}}.

Match kinds:
  rm         structured: rm with flags (recursive, force) and a target class
             (root, home, outside_cwd, cwd_self, cwd_is_home, dynamic, any)
  argv       structured: a program (and git subcommand) with option/word conditions
  substring  the published text test on the raw command (as the source rule does it)
  regex      the published regular expression on the raw command
  prefix     the datapce guard v0 test: a normalized segment starts with the pattern

Python 3.9+, stdlib only.
"""
import hashlib
import json
import os
import posixpath
import re
import shlex
from typing import Dict, List, Optional, Tuple

from . import shellparse

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(HERE, "rules")

ACTIONS = ("deny", "ask")
KINDS = ("rm", "argv", "substring", "regex", "prefix")
RM_FLAGS = ("recursive", "force")
RM_TARGETS = ("root", "home", "outside_cwd", "cwd_self", "cwd_is_home", "dynamic", "any")
COND_KEYS = ("long", "short", "word", "first", "pos_prefix", "pos_contains", "after_dd",
             "not", "all", "any")

TEMP_ROOTS = ("/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/var/folders",
              "/private/var/folders")
TEMP_ENV = {"TMPDIR", "TMP", "TEMP", "TEMPDIR", "RUNNER_TEMP"}
DELETE_CMDS = {"rm", "rmdir", "unlink", "shred", "trash"}
_GIT_ARG_OPTS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
                 "--config-env", "--super-prefix"}
_VAR_RE = re.compile(r"^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?:[:#%/][^}]*)?\}|([A-Za-z_][A-Za-z0-9_]*))")


class RulesetError(Exception):
    """The rule set is not valid."""


class Verdict:
    __slots__ = ("action", "rule", "temp_target", "heredoc_only")

    def __init__(self, action: str, rule: Optional[str], temp_target: bool = False,
                 heredoc_only: bool = False):
        self.action = action
        self.rule = rule
        self.temp_target = temp_target
        self.heredoc_only = heredoc_only

    def __repr__(self) -> str:
        return "Verdict(%s, %s, temp=%s, heredoc_only=%s)" % (
            self.action, self.rule, self.temp_target, self.heredoc_only)


# ---------------------------------------------------------------- paths

def _norm(p: str) -> str:
    p = re.sub(r"/{2,}", "/", p)
    p = posixpath.normpath(p)
    return "/" if p.startswith("//") else p


def _strip_glob(p: str) -> str:
    while len(p) > 1 and (p.endswith("/*") or p.endswith("/.") or p.endswith("/")):
        p = p[:-2] if p.endswith(("/*", "/.")) else p[:-1]
    return p or "/"


def resolve(tok: str, cwd: Optional[str], home: str, tvars: set,
            lvars: Optional[Dict[str, Optional[str]]] = None, _depth: int = 0
            ) -> Tuple[str, Optional[str]]:
    """Return (kind, path). kind: path, temp (a temp-dir variable), dynamic, unknown.

    lvars: variables set to a literal value earlier in the same call ($S after S=/tmp/x).
    """
    if not tok:
        return "unknown", None
    if tok.startswith("~"):
        if tok == "~" or tok.startswith("~/"):
            return "path", _norm(home + tok[1:])
        return "unknown", None
    if tok.startswith("$"):
        m = _VAR_RE.match(tok)
        if not m:
            return "dynamic", None
        name = m.group(1) or m.group(2)
        rest = tok[m.end():]
        if "$" in rest or "`" in rest or "__DPS" in rest:
            return "dynamic", None
        if name == "HOME":
            return "path", _norm(home + rest)
        if name == "PWD" and cwd:
            return "path", _norm(cwd + rest)
        if name in TEMP_ENV or name in tvars:
            return "temp", None
        if lvars and isinstance(lvars.get(name), str) and _depth < 4:
            return resolve(lvars[name] + rest, cwd, home, tvars, lvars, _depth + 1)
        return "dynamic", None
    if "$" in tok or "`" in tok or "__DPS" in tok:
        return "dynamic", None
    if tok.startswith("/"):
        return "path", _norm(tok)
    if cwd:
        return "path", _norm(posixpath.join(cwd, tok))
    return "unknown", None


def is_temp_path(path: str) -> bool:
    return any(path == r or path.startswith(r + "/") for r in TEMP_ROOTS)


def _under(path: str, base: str) -> bool:
    return path == base or path.startswith(base.rstrip("/") + "/")


# ---------------------------------------------------------------- call context

class Context:
    def __init__(self, raw: str, cwd: Optional[str], home: str):
        self.raw = raw or ""
        self.home = _norm(home) if home else "/nonexistent-home"
        self.cmds = shellparse.parse(self.raw)
        self.tvars = self.cmds.temp_vars
        self.lvars = self.cmds.vars
        self._code: Optional[str] = None
        self.cwds: List[Optional[str]] = []
        cur = _norm(cwd) if cwd else None
        for c in self.cmds:
            self.cwds.append(cur)
            if c.argv and c.argv[0] == "cd" and c.depth == 0:
                args = [a for a in c.argv[1:] if not a.startswith("-")]
                if not args:
                    cur = self.home
                else:
                    kind, p = resolve(args[0], cur, self.home, self.tvars, self.lvars)
                    cur = p if kind == "path" else None
        self._legacy = None

    @property
    def code(self) -> str:
        """The raw text without heredoc bodies."""
        if self._code is None:
            self._code = shellparse.heredoc_free(self.raw)
        return self._code

    def operands(self, idx: int) -> List[Tuple[str, Optional[str]]]:
        c = self.cmds[idx]
        if not c.argv:
            return []
        base = os.path.basename(c.argv[0])
        if base == "git":  # the target of a git command is its repo: -C <path>, else the cwd
            args = c.argv[1:]
            for k, a in enumerate(args[:-1]):
                if a == "-C":
                    return [(args[k + 1], self.cwds[idx])]
                if not a.startswith("-"):
                    break
            return [(".", self.cwds[idx])] if self.cwds[idx] else []
        pos = _positionals(c.argv[1:])
        if base not in DELETE_CMDS:
            pos = [p for p in pos if _path_like(p)]
        return [(p, self.cwds[idx]) for p in pos]

    def all_operands(self) -> List[Tuple[str, Optional[str]]]:
        out = []
        for i in range(len(self.cmds)):
            out.extend(self.operands(i))
        return out

    def is_temp(self, ops: List[Tuple[str, Optional[str]]]) -> bool:
        if not ops:
            return False
        for tok, cwd in ops:
            kind, p = resolve(tok, cwd, self.home, self.tvars, self.lvars)
            if kind == "temp":
                continue
            if kind != "path" or not is_temp_path(p):
                return False
        return True

    def legacy_segments(self) -> List[str]:
        if self._legacy is None:
            self._legacy = [_legacy_normalize(s) for s in _legacy_split(self.raw)]
        return self._legacy


def _positionals(args: List[str]) -> List[str]:
    out, dd = [], False
    for a in args:
        if not dd and a == "--":
            dd = True
            continue
        if not dd and a.startswith("-") and a != "-":
            continue
        out.append(a)
    return out


def _path_like(tok: str) -> bool:
    if "://" in tok:
        return False
    return tok.startswith(("/", "~", ".", "$")) or "/" in tok


# ---------------------------------------------------------------- legacy guard v0 segmenting
# Copied from datapce guard v0 (guard.py) so `prefix` rules give the v0 results.

_L_SPLIT = re.compile(r"&&|\|\||;|\||\r?\n|(?<![<>&])&(?![>&])")
_L_ENV = re.compile(r"""^[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"(?:[^"\\]|\\.)*"|[^\s'"]*)(?:\s+|$)""")
_L_WS = re.compile(r"\s+")


def _legacy_split(cmd: str) -> List[str]:
    return [s.strip() for s in _L_SPLIT.split(cmd) if s.strip()]


def _legacy_normalize(seg: str) -> str:
    s = seg.strip()
    while True:
        before = s
        m = _L_ENV.match(s)
        while m:
            s = s[m.end():]
            m = _L_ENV.match(s)
        if s == "sudo" or s.startswith("sudo ") or s.startswith("sudo\t"):
            toks = s.split()[1:]
            i = 0
            while i < len(toks) and toks[i].startswith("-"):
                if toks[i] == "--":
                    i += 1
                    break
                i += 2 if toks[i] in {"-u", "-g", "-U", "-C", "-p", "-r", "-t", "-D", "-R",
                                      "-T", "-h"} else 1
            s = " ".join(toks[i:])
        if s == before:
            break
    return _L_WS.sub(" ", s).strip()


# ---------------------------------------------------------------- matchers
# Each matcher returns None (no hit) or a list of (operand, cwd) pairs for the temp test.

def _rm_parse(argv: List[str]) -> Tuple[set, List[str]]:
    flags, targets, dd = set(), [], False
    for a in argv[1:]:
        if not dd and a == "--":
            dd = True
            continue
        if not dd and a.startswith("--"):
            if a == "--recursive":
                flags.add("recursive")
            elif a == "--force":
                flags.add("force")
            continue
        if not dd and a.startswith("-") and len(a) > 1:
            if "r" in a or "R" in a:
                flags.add("recursive")
            if "f" in a:
                flags.add("force")
            continue
        targets.append(a)
    return flags, targets


def _rm_target_hit(classes, written, tok, cwd, ctx: Context) -> bool:
    if written and not any(tok.startswith(w) or tok.startswith('"' + w) for w in written):
        return False
    kind, p = resolve(tok, cwd, ctx.home, ctx.tvars, ctx.lvars)
    for cl in classes:
        if cl == "any":
            return True
        if cl == "dynamic":
            if kind == "dynamic":
                return True
            continue
        if kind != "path":
            continue
        core = _strip_glob(p)
        if cl == "root" and core == "/":
            return True
        if cl == "home" and core == ctx.home:
            return True
        if cl == "cwd_self" and cwd and p == cwd:
            return True
        if cl == "cwd_is_home" and cwd and cwd == ctx.home and not tok.startswith(("/", "~", "$")) \
                and not is_temp_path(p):
            return True
        if cl == "outside_cwd" and cwd and not is_temp_path(p) and not _under(p, cwd):
            return True
    return False


def _m_rm(m: dict, ctx: Context):
    need = set(m.get("flags", []))
    for i, c in enumerate(ctx.cmds):
        if not c.argv or os.path.basename(c.argv[0]) != "rm":
            continue
        flags, targets = _rm_parse(c.argv)
        if not need <= flags:
            continue
        cwd = ctx.cwds[i]
        for t in targets:
            if _rm_target_hit(m["target"], m.get("written"), t, cwd, ctx):
                return [(x, cwd) for x in targets]
    return None


def _git_split(args: List[str]) -> Tuple[Optional[str], List[str]]:
    i = 0
    while i < len(args):
        a = args[i]
        if not a.startswith("-"):
            return a, args[i + 1:]
        i += 2 if a in _GIT_ARG_OPTS else 1
    return None, []


def _long_hit(tokens: List[str], opt: str, abbrev: bool) -> bool:
    for t in tokens:
        if not t.startswith("--"):
            continue
        name = t.split("=", 1)[0]
        if name == opt:
            return True
        if abbrev and len(name) >= 4 and opt.startswith(name):
            return True
    return False


def _short_hit(tokens: List[str], ch: str) -> bool:
    return any(re.fullmatch(r"-[A-Za-z0-9]+", t) and ch in t[1:] for t in tokens)


def _cond(c: dict, rest: List[str], before: List[str], after: List[str], abbrev: bool) -> bool:
    pos = [t for t in before if not t.startswith("-")] + after
    if "long" in c:
        return _long_hit(before, c["long"], abbrev)
    if "short" in c:
        return _short_hit(before, c["short"])
    if "word" in c:
        return c["word"] in rest
    if "first" in c:
        return bool(rest) and rest[0] == c["first"]
    if "pos_prefix" in c:
        return any(p.startswith(c["pos_prefix"]) for p in pos)
    if "pos_contains" in c:
        return any(c["pos_contains"] in p for p in pos)
    if "after_dd" in c:
        return bool(after) == bool(c["after_dd"])
    if "not" in c:
        return not _cond(c["not"], rest, before, after, abbrev)
    if "all" in c:
        return all(_cond(x, rest, before, after, abbrev) for x in c["all"])
    if "any" in c:
        return any(_cond(x, rest, before, after, abbrev) for x in c["any"])
    return False


def _m_argv(m: dict, ctx: Context):
    cmds = set(m["cmd"])
    subs = set(m["sub"]) if m.get("sub") else None
    for i, c in enumerate(ctx.cmds):
        if not c.argv or os.path.basename(c.argv[0]) not in cmds:
            continue
        args = c.argv[1:]
        is_git = os.path.basename(c.argv[0]) == "git"
        if is_git:
            sub, rest = _git_split(args)
        else:
            sub, rest = (args[0], args[1:]) if args else (None, [])
        if subs is not None:
            if sub not in subs:
                continue
        else:
            rest = args
        if "--" in rest:
            k = rest.index("--")
            before, after = rest[:k], rest[k + 1:]
        else:
            before, after = rest, []
        ok = all(_cond(x, rest, before, after, is_git) for x in m.get("all", []))
        if ok and m.get("any"):
            ok = any(_cond(x, rest, before, after, is_git) for x in m["any"])
        if ok and m.get("none"):
            ok = not any(_cond(x, rest, before, after, is_git) for x in m["none"])
        if ok:
            return ctx.operands(i)
    return None


def _attribute(test, ctx: Context):
    for i, c in enumerate(ctx.cmds):
        if c.argv and test(c.text):
            return ctx.operands(i)
    return ctx.all_operands()


def _substring_test(m: dict):
    lower = bool(m.get("lower"))
    alls = [s.lower() if lower else s for s in m.get("all", [])]
    anys = [s.lower() if lower else s for s in m.get("any", [])]
    nones = [s.lower() if lower else s for s in m.get("none", [])]

    def test(text: str) -> bool:
        t = text.lower() if lower else text
        if not all(s in t for s in alls):
            return False
        if anys and not any(s in t for s in anys):
            return False
        return not any(s in t for s in nones)
    return test


def _m_substring(m: dict, ctx: Context):
    test = m["_test"]
    if not test(ctx.raw):
        return None
    return _attribute(test, ctx)


def _regex_test(m: dict):
    rx, pf = m["_rx"], m.get("prefilter")
    lower = bool(m.get("ignore_case"))
    if pf and lower:
        pf = [x.lower() for x in pf]

    def test(text: str) -> bool:
        if pf:
            t = text.lower() if lower else text
            if not any(x in t for x in pf):
                return False
        return bool(rx.search(text))
    return test


def _m_regex(m: dict, ctx: Context):
    test = m["_test"]
    if not test(ctx.raw):
        return None
    return _attribute(test, ctx)


def _prefix_test(m: dict):
    pat = _L_WS.sub(" ", m["pattern"]).strip()

    def test(text: str) -> bool:
        return any(_legacy_normalize(s).startswith(pat) for s in _legacy_split(text))
    return test


def _m_prefix(m: dict, ctx: Context):
    pat = _L_WS.sub(" ", m["pattern"]).strip()
    for seg in ctx.legacy_segments():
        if seg.startswith(pat):
            try:
                words = shlex.split(seg)
            except ValueError:
                words = seg.split()
            if not words:
                continue
            pos = _positionals(words[1:])
            if os.path.basename(words[0]) not in DELETE_CMDS:
                pos = [p for p in pos if _path_like(p)]
            cwd = ctx.cwds[0] if ctx.cwds else None
            return [(p, cwd) for p in pos]
    return None


MATCHERS = {"rm": _m_rm, "argv": _m_argv, "substring": _m_substring, "regex": _m_regex,
            "prefix": _m_prefix}


# ---------------------------------------------------------------- validation and loading

def _check_cond(c) -> None:
    if not isinstance(c, dict) or len(c) != 1 or next(iter(c)) not in COND_KEYS:
        raise RulesetError("bad argv condition: %r" % (c,))
    k, v = next(iter(c.items()))
    if k == "not":
        _check_cond(v)
    elif k in ("all", "any"):
        if not isinstance(v, list) or not v:
            raise RulesetError("empty condition list")
        for x in v:
            _check_cond(x)


def _check_match(m) -> dict:
    if not isinstance(m, dict) or m.get("kind") not in KINDS:
        raise RulesetError("unsupported match kind")
    m = dict(m)
    kind = m["kind"]
    if kind == "rm":
        if not set(m.get("flags", [])) <= set(RM_FLAGS):
            raise RulesetError("unknown rm flag")
        t = m.get("target")
        if not isinstance(t, list) or not t or not set(t) <= set(RM_TARGETS):
            raise RulesetError("unknown rm target class")
    elif kind == "argv":
        if not isinstance(m.get("cmd"), list) or not m["cmd"]:
            raise RulesetError("argv rule needs cmd")
        if not (m.get("all") or m.get("any") or m.get("sub")):
            raise RulesetError("argv rule needs a condition")
        for key in ("all", "any", "none"):
            for c in m.get(key, []):
                _check_cond(c)
    elif kind == "substring":
        for key in ("all", "any", "none"):
            v = m.get(key, [])
            if not isinstance(v, list) or not all(isinstance(s, str) and s for s in v):
                raise RulesetError("substring lists must hold text")
        if not (m.get("all") or m.get("any")):
            raise RulesetError("substring rule needs all or any")
        m["_test"] = _substring_test(m)
    elif kind == "regex":
        try:
            m["_rx"] = re.compile(m["pattern"], re.I if m.get("ignore_case") else 0)
        except (KeyError, TypeError, re.error) as e:
            raise RulesetError("regex does not compile") from e
        pf = m.get("prefilter")
        if pf is not None and (not isinstance(pf, list) or not pf
                               or not all(isinstance(x, str) and x for x in pf)):
            raise RulesetError("prefilter must be a list of text")
        m["_test"] = _regex_test(m)
    elif kind == "prefix":
        if not isinstance(m.get("pattern"), str) or not m["pattern"].strip():
            raise RulesetError("empty prefix pattern")
        m["_test"] = _prefix_test(m)
    return m


class RuleSet:
    def __init__(self, name: str, rules: List[dict], meta: dict, sha256: str):
        self.name = name
        self.rules = rules
        self.meta = meta
        self.sha256 = sha256

    @classmethod
    def from_doc(cls, doc, sha256: str = "") -> "RuleSet":
        if not isinstance(doc, dict) or not isinstance(doc.get("name"), str):
            raise RulesetError("rule set needs a name")
        raw = doc.get("rules")
        if not isinstance(raw, list) or not raw:
            raise RulesetError("rules must be a non-empty list")
        names, rules = set(), []
        for r in raw:
            if not isinstance(r, dict):
                raise RulesetError("rule must be an object")
            n = r.get("name")
            if not isinstance(n, str) or not n or n in names:
                raise RulesetError("rule name missing or duplicate")
            if r.get("action") not in ACTIONS:
                raise RulesetError("unsupported action")
            names.add(n)
            rules.append({"name": n, "action": r["action"], "match": _check_match(r.get("match"))})
        meta = {k: v for k, v in doc.items() if k != "rules"}
        return cls(doc["name"], rules, meta, sha256)

    def evaluate(self, command: str, cwd: Optional[str], home: str) -> Verdict:
        return self.evaluate_ctx(Context(command, cwd, home))

    def evaluate_ctx(self, ctx: Context) -> Verdict:
        """First deny rule in file order, else first ask rule, else pass."""
        for action in ACTIONS:
            for r in self.rules:
                if r["action"] != action:
                    continue
                m = r["match"]
                ops = MATCHERS[m["kind"]](m, ctx)
                if ops is not None:
                    text_rule = "_test" in m
                    heredoc_only = text_rule and ctx.code != ctx.raw and not m["_test"](ctx.code)
                    return Verdict(action, r["name"], ctx.is_temp(ops), heredoc_only)
        return Verdict("pass", None, False)


def available() -> List[str]:
    if not os.path.isdir(RULES_DIR):
        return []
    return sorted(f[:-5] for f in os.listdir(RULES_DIR) if f.endswith(".json"))


def load(name_or_path: str) -> RuleSet:
    if os.sep in name_or_path or name_or_path.endswith(".json"):
        path = name_or_path
    else:
        path = os.path.join(RULES_DIR, name_or_path + ".json")
    if not os.path.isfile(path):
        raise RulesetError("no rule set named %r (try: %s)" % (name_or_path, ", ".join(available())))
    with open(path, "rb") as f:
        raw = f.read()
    try:
        doc = json.loads(raw.decode("utf-8"))
    except ValueError as e:
        raise RulesetError("rule set is not JSON") from e
    return RuleSet.from_doc(doc, hashlib.sha256(raw).hexdigest())
