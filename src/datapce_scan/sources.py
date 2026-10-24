"""Read tool calls from Claude Code transcripts on disk. Read-only.

Layout: <projects>/<project-dir>/<session>.jsonl (top level). Subagent transcripts live in
<projects>/<project-dir>/<session>/subagents/... and are read only with include_subagents.
Each assistant line holds tool_use blocks: {"type": "tool_use", "id", "name", "input"}.

Python 3.9+, stdlib only.
"""
import glob
import io
import json
import os
from typing import List, NamedTuple, Optional, Tuple

from . import secretkinds

DEFAULT_PROJECTS = os.path.join("~", ".claude", "projects")


class Call(NamedTuple):
    ts: str
    session: Optional[str]
    tool: str
    tool_use_id: Optional[str]
    command: Optional[str]
    cwd: Optional[str]
    outcome: Optional[str] = None  # from the tool_result: see OUTCOMES; None = no result line
    target: Optional[str] = None   # file path (Read, Edit, Write, NotebookEdit, Grep, Glob) or URL
    input_kinds: Tuple[str, ...] = ()   # secret-shaped value kinds in the input (never values)
    input_ph: Tuple[str, ...] = ()      # of these, kinds that look like placeholders only
    output_kinds: Tuple[str, ...] = ()  # secret-shaped value kinds in the tool result
    output_ph: Tuple[str, ...] = ()


class ReadResult(NamedTuple):
    calls: List[Call]
    files: int
    bad_lines: int
    duplicates: int
    include_subagents: bool


_TARGET_KEYS = {"Read": ("file_path",), "Edit": ("file_path",), "Write": ("file_path",),
                "MultiEdit": ("file_path",), "NotebookEdit": ("notebook_path",),
                "Grep": ("path",), "Glob": ("path",), "WebFetch": ("url",)}
OUTCOMES = ("ok", "error", "classifier-no-verdict", "classifier-denied", "safety-check-denied",
            "rule-denied", "user-rejected")
_NO_VERDICT = ("cannot determine the safety", "no safety verdict", "returned no verdict")


def outcome_of(text: str, is_error: bool) -> str:
    """Label a tool result. Only fixed phrases of Claude Code messages are used."""
    if not is_error:
        return "ok"
    t = text[:600]
    if any(p in t for p in _NO_VERDICT):
        return "classifier-no-verdict"
    if "denied by the Claude Code auto mode classifier" in t:
        return "classifier-denied"
    if "denied by a built-in Claude Code safety" in t:
        return "safety-check-denied"
    if "doesn't want to proceed" in t:
        return "user-rejected"
    if "Permission to use" in t and "has been denied" in t:
        return "rule-denied"
    return "error"


_INPUT_KEYS = ("command", "content", "new_string", "new_source")


def _input_text(inp: dict) -> str:
    parts = [inp[k] for k in _INPUT_KEYS if isinstance(inp.get(k), str)]
    edits = inp.get("edits")
    if isinstance(edits, list):
        parts += [e["new_string"] for e in edits
                  if isinstance(e, dict) and isinstance(e.get("new_string"), str)]
    return "\n".join(parts)


def _result_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(x.get("text", "") for x in content
                        if isinstance(x, dict) and isinstance(x.get("text"), str))
    return ""


def _files(root: str, include_subagents: bool) -> List[str]:
    if not os.path.isdir(root):
        return []
    if not include_subagents:
        out = glob.glob(os.path.join(glob.escape(root), "*", "*.jsonl"))
    else:
        out = []
        for dp, _, fs in os.walk(root):
            out.extend(os.path.join(dp, f) for f in fs if f.endswith(".jsonl"))
    # Regular files only: a dangling link or a directory named *.jsonl is skipped.
    return sorted(p for p in out if os.path.isfile(p))


def _open_or_empty(path: str):
    """The file for reading; an empty stream if it cannot be opened (no traceback, no path printed)."""
    try:
        return open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return io.StringIO("")


def read_claude_code(root: Optional[str] = None, include_subagents: bool = False,
                     since: Optional[str] = None, until: Optional[str] = None) -> ReadResult:
    root = os.path.expanduser(root or DEFAULT_PROJECTS)
    files = _files(root, include_subagents)
    calls: List[Call] = []
    seen = set()
    results = {}
    bad = dup = 0
    for path in files:
        with _open_or_empty(path) as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    o = json.loads(line)
                except ValueError:
                    bad += 1
                    continue
                if not isinstance(o, dict):
                    bad += 1
                    continue
                if o.get("type") == "user":
                    _read_results(o, results)
                    continue
                if o.get("type") != "assistant":
                    continue
                ts = o.get("timestamp")
                if not isinstance(ts, str) or len(ts) < 13:
                    continue
                day = ts[:10]
                if (since and day < since) or (until and day > until):
                    continue
                msg = o.get("message")
                content = msg.get("content") if isinstance(msg, dict) else None
                if not isinstance(content, list):
                    continue
                for b in content:
                    if not isinstance(b, dict) or b.get("type") != "tool_use":
                        continue
                    tid = b.get("id") if isinstance(b.get("id"), str) else None
                    if tid is not None:
                        if tid in seen:
                            dup += 1
                            continue
                        seen.add(tid)
                    name = b.get("name") if isinstance(b.get("name"), str) else "(unknown)"
                    inp = b.get("input") if isinstance(b.get("input"), dict) else {}
                    cmd = inp.get("command") if name == "Bash" else None
                    cwd = o.get("cwd") if isinstance(o.get("cwd"), str) else None
                    tgt = None
                    for key in _TARGET_KEYS.get(name, ()):
                        if isinstance(inp.get(key), str):
                            tgt = inp[key]
                            break
                    ik, iph = secretkinds.summarize(_input_text(inp))
                    calls.append(Call(ts, o.get("sessionId") if isinstance(o.get("sessionId"), str)
                                      else None, name, tid, cmd if isinstance(cmd, str) else None,
                                      cwd, None, tgt, ik, iph))
    calls = [c._replace(outcome=results[c.tool_use_id][0], output_kinds=results[c.tool_use_id][1],
                        output_ph=results[c.tool_use_id][2])
             if c.tool_use_id in results else c for c in calls]
    calls.sort(key=lambda c: (c.ts, c.tool_use_id or ""))
    return ReadResult(calls, len(files), bad, dup, include_subagents)


def _read_results(o: dict, results: dict) -> None:
    msg = o.get("message")
    content = msg.get("content") if isinstance(msg, dict) else None
    if not isinstance(content, list):
        return
    for b in content:
        if isinstance(b, dict) and b.get("type") == "tool_result" \
                and isinstance(b.get("tool_use_id"), str):
            t = _result_text(b.get("content"))
            ok, ph = secretkinds.summarize(t)
            results[b["tool_use_id"]] = (outcome_of(t, bool(b.get("is_error"))), ok, ph)
