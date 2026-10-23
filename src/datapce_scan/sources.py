"""Read tool calls from Claude Code transcripts on disk. Read-only.

Layout: <projects>/<project-dir>/<session>.jsonl (top level). Subagent transcripts live in
<projects>/<project-dir>/<session>/subagents/... and are read only with include_subagents.
Each assistant line holds tool_use blocks: {"type": "tool_use", "id", "name", "input"}.

Python 3.9+, stdlib only.
"""
import glob
import json
import os
from typing import List, NamedTuple, Optional

DEFAULT_PROJECTS = os.path.join("~", ".claude", "projects")


class Call(NamedTuple):
    ts: str
    session: Optional[str]
    tool: str
    tool_use_id: Optional[str]
    command: Optional[str]
    cwd: Optional[str]


class ReadResult(NamedTuple):
    calls: List[Call]
    files: int
    bad_lines: int
    duplicates: int
    include_subagents: bool


def _files(root: str, include_subagents: bool) -> List[str]:
    if not os.path.isdir(root):
        return []
    if not include_subagents:
        return sorted(glob.glob(os.path.join(glob.escape(root), "*", "*.jsonl")))
    out = []
    for dp, _, fs in os.walk(root):
        out.extend(os.path.join(dp, f) for f in fs if f.endswith(".jsonl"))
    return sorted(out)


def read_claude_code(root: Optional[str] = None, include_subagents: bool = False,
                     since: Optional[str] = None, until: Optional[str] = None) -> ReadResult:
    root = os.path.expanduser(root or DEFAULT_PROJECTS)
    files = _files(root, include_subagents)
    calls: List[Call] = []
    seen = set()
    bad = dup = 0
    for path in files:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
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
                    calls.append(Call(ts, o.get("sessionId") if isinstance(o.get("sessionId"), str)
                                      else None, name, tid, cmd if isinstance(cmd, str) else None,
                                      cwd))
    calls.sort(key=lambda c: (c.ts, c.tool_use_id or ""))
    return ReadResult(calls, len(files), bad, dup, include_subagents)
