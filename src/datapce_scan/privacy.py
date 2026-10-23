"""Output privacy: labels and a last check before anything is printed.

Counts and labels only. A label that looks like an e-mail address or a secret becomes
"(redacted)". A label with a path keeps the basename only. The final output text must not hold
an e-mail address or a home-directory path; check_output stops the print if it does.

Python 3.9+, stdlib only.
"""
import os
import re

REDACTED = "(redacted)"
MAX_LABEL = 40

EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
HOME_DIRS = re.compile(r"/(?:Users|home)/[^/\s\"'|)]+")
_SECRET_TOKENS = [
    re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{8,}"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"),
    re.compile(r"(?=[A-Za-z0-9+/_-]*\d)(?=[A-Za-z0-9+/_-]*[A-Za-z])[A-Za-z0-9+/_-]{32,}={0,2}"),
]
_BEARER = re.compile(r"(?i)\b(bearer|token|basic)(\s+)([A-Za-z0-9._~+/=-]+)")
_NAMED = re.compile(r"(?i)\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PWD_?KEY|API_?KEY|ACCESS_?KEY"
                    r"|PRIVATE_?KEY|CREDENTIAL)[A-Z0-9_]*)(\s*[=:]\s*)('[^']*'|\"[^\"]*\"|[^\s;&|]+)")
_URL_CRED = re.compile(r"(://[^/\s:@]+:)([^@\s/]+)(@)")
_FLAG_PW = re.compile(r"(?i)(--?(?:password|passwd|token|secret|api-key)[= ])(\S+)")


class PrivacyError(ValueError):
    pass


def _looks_secret(s: str) -> bool:
    return bool(EMAIL.search(s)) or any(rx.search(s) for rx in _SECRET_TOKENS)


def safe_label(s: str) -> str:
    s = str(s)
    if _looks_secret(s):
        return REDACTED
    if "/" in s.rstrip("/"):
        s = os.path.basename(s.rstrip("/"))
    if len(s) > MAX_LABEL:
        s = s[:MAX_LABEL - 3] + "..."
    return s


def redact(text: str, home: str = "") -> str:
    """Mask e-mail addresses and secret-like values in text shown with --show-examples."""
    t = EMAIL.sub("<email>", text)
    t = _URL_CRED.sub(r"\1<redacted>\3", t)
    t = _BEARER.sub(r"\1\2<redacted>", t)
    t = _NAMED.sub(r"\1\2<redacted>", t)
    t = _FLAG_PW.sub(r"\1<redacted>", t)
    for rx in _SECRET_TOKENS:
        t = rx.sub("<redacted>", t)
    if home and home != "/":
        t = t.replace(home, "~")
    return t


def check_output(text: str, home: str = "") -> str:
    bad = []
    if EMAIL.search(text):
        bad.append("e-mail address")
    if (home and home != "/" and home in text) or HOME_DIRS.search(text):
        bad.append("home path")
    if bad:
        raise PrivacyError("output stopped, it holds: " + ", ".join(bad))
    return text
