"""Secret-shaped value kinds in text. Returns kind names and placeholder flags, never values.

Python 3.9+, stdlib only. No imports from this package (sources.py uses it).
"""
import re
from typing import Dict, List

# Every pattern is linear in the text length: no unbounded run is followed by more pattern
# that can fail (that would backtrack over the run from each start). JWT uses a token scan.
KINDS = [
    ("private key block", re.compile(r"-----BEGIN (?:[A-Z]{1,20} ){0,8}PRIVATE KEY-----")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("sk- API key", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_-]{20,}")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
]
JWT_KIND = "JWT"
_JWT_RUN = re.compile(r"[A-Za-z0-9_.-]+")
_JWT_START = re.compile(r"(?:^|-)eyJ")
_WORDCH = re.compile(r"\w")
NAMED = re.compile(r"(?i)\b[A-Z0-9_]{0,64}(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|"
                   r"PRIVATE_?KEY|CLIENT_?SECRET)[A-Z0-9_]{0,64}['\"]?\s{0,8}[=:]\s{0,8}['\"]?"
                   r"([A-Za-z0-9/+_.-]{16,})")
NAMED_KIND = "named secret assignment"
_PLACEHOLDER = re.compile(r"(?i)example|xxxx|abcdefgh|1234567890|0000000000|dummy|fake|sample|"
                          r"placeholder|your[_-]|redacted|changeme|test|\*\*\*\*")
_MAX = 2_000_000


def _jwts(t: str) -> List[str]:
    """JWT-shaped values: eyJ<10+>.eyJ<10+>.<10+> (segments of [A-Za-z0-9_-]), found with one
    linear pass over runs of [A-Za-z0-9_.-]. Same matches as the regex
    \\beyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}, without backtracking."""
    out = []
    for run in _JWT_RUN.finditer(t):
        parts = run.group(0).split(".")
        pos = run.start()
        starts = []  # absolute start of each part
        for part in parts:
            starts.append(pos)
            pos += len(part) + 1
        i = 0
        while i + 2 < len(parts):
            p = parts[i]
            m = _JWT_START.search(p)
            k = None if m is None else m.end() - 3
            if k == 0 and starts[i] > 0 and _WORDCH.match(t[starts[i] - 1]):
                m = _JWT_START.search(p, 1)  # no word boundary before the run: next '-eyJ'
                k = None if m is None else m.end() - 3
            if (k is not None and len(p) - k >= 13 and parts[i + 1].startswith("eyJ")
                    and len(parts[i + 1]) >= 13 and len(parts[i + 2]) >= 10):
                out.append("%s.%s.%s" % (p[k:], parts[i + 1], parts[i + 2]))
                i += 3
                continue
            i += 1
    return out


def value_kinds(text: str) -> Dict[str, List[bool]]:
    """{kind: [is_placeholder, ...]} for each secret-shaped value in text."""
    if not text:
        return {}
    t = text[:_MAX]
    out: Dict[str, List[bool]] = {}
    for name, rx in KINDS:
        for m in rx.finditer(t):
            out.setdefault(name, []).append(bool(_PLACEHOLDER.search(m.group(0))))
    for v in _jwts(t):
        out.setdefault(JWT_KIND, []).append(bool(_PLACEHOLDER.search(v)))
    for m in NAMED.finditer(t):
        v = m.group(1)
        if not (re.search(r"[A-Za-z]", v) and re.search(r"\d", v)):
            continue
        if v.startswith(("sk-", "gh", "AKIA", "ASIA", "xox", "glpat-", "AIza", "eyJ")):
            continue  # already counted as its own kind
        out.setdefault(NAMED_KIND, []).append(bool(_PLACEHOLDER.search(v)))
    return out


def summarize(text: str):
    """(kinds, placeholder_only_kinds) as sorted tuples."""
    k = value_kinds(text)
    return tuple(sorted(k)), tuple(sorted(n for n, v in k.items() if all(v)))
