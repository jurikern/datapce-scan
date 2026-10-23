"""datapce-scan command line. Read-only. No network calls.

  datapce-scan [options]                     what ran: counts by tool, command family, repo, day
  datapce-scan replay --rules NAME [options] what a rule set would have denied in past Bash calls
  datapce-scan rules                         the packaged rule sets, with source and licence

Python 3.9+, stdlib only.
"""
import argparse
import os
import sys
from typing import List, Optional

from . import __version__, privacy, report, rules, sources

COMMANDS = ("summary", "replay", "rules")


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--projects", default=sources.DEFAULT_PROJECTS,
                   help="Claude Code projects directory (default: ~/.claude/projects)")
    p.add_argument("--include-subagents", action="store_true",
                   help="also read subagent transcripts under each session")
    p.add_argument("--since", help="first UTC day to read, YYYY-MM-DD")
    p.add_argument("--until", help="last UTC day to read, YYYY-MM-DD")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--json", dest="fmt", action="store_const", const="json", help="JSON output")
    g.add_argument("--tsv", dest="fmt", action="store_const", const="tsv", help="TSV output")
    p.set_defaults(fmt="table")


def _parser(cmd: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="datapce-scan" if cmd == "summary" else "datapce-scan " + cmd,
        description=("Read-only scan of coding-agent logs on this machine. Nothing is sent. "
                     "No command text is printed."))
    p.add_argument("--version", action="version", version="datapce-scan " + __version__)
    if cmd == "rules":
        return p
    _common(p)
    if cmd == "summary":
        p.add_argument("--hash-repos", action="store_true",
                       help="show repos as short hashes, not directory basenames")
        p.add_argument("--top", type=int, default=10, help="rows per table (default 10)")
        p.add_argument("--show-local-families", action="store_true",
                       help="print every command family name, also names that are not on the "
                            "public list (off by default; can show private script names)")
    else:
        p.add_argument("--rules", required=True,
                       help="rule set name, comma list, 'all', or a path to a rule-set JSON file")
        p.add_argument("--show-examples", nargs="?", type=int, const=3, default=0, metavar="N",
                       help="print up to N matched commands per rule to this terminal (off by "
                            "default; table format only)")
    return p


def _emit(text: str, home: str) -> int:
    try:
        privacy.check_output(text, home)
    except privacy.PrivacyError as e:
        print("datapce-scan: %s" % e, file=sys.stderr)
        return 3
    print(text)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv.pop(0) if argv and argv[0] in COMMANDS else "summary"
    a = _parser(cmd).parse_args(argv)
    home = os.path.expanduser("~")

    if cmd == "rules":
        lines = [report.header(), "", "Packaged rule sets (use the name with: replay --rules NAME)"]
        for n in rules.available():
            s = rules.load(n)
            m = s.meta
            lines.append("")
            lines.append("  %s  (%d rules, licence %s)" % (n, len(s.rules), m.get("licence")))
            lines.append("    reuse:   %s" % m.get("reuse"))
            lines.append("    source:  %s  (fetched %s)" % (m.get("source_url"), m.get("fetched")))
        return _emit("\n".join(lines), home)

    if cmd == "replay":
        names = rules.available() if a.rules == "all" else [x for x in a.rules.split(",") if x]
        try:
            sets = [rules.load(n) for n in names]
        except rules.RulesetError as e:
            print("datapce-scan: %s" % e, file=sys.stderr)
            return 2
        if a.show_examples:
            if a.fmt != "table":
                print("datapce-scan: --show-examples works with the table format only",
                      file=sys.stderr)
                return 2
            if not sys.stdout.isatty():
                print("datapce-scan: --show-examples prints to a terminal only, not to a pipe "
                      "or file", file=sys.stderr)
                return 2

    res = sources.read_claude_code(a.projects, a.include_subagents, a.since, a.until)

    if cmd == "summary":
        s = report.summarize(res, home, hash_repos=a.hash_repos, top=a.top,
                             local_families=a.show_local_families)
        return _emit(report.render_summary(s, a.fmt), home)

    results = report.replay_many(res, sets, home, examples=a.show_examples)
    code = _emit(report.render_replay(results, a.fmt), home)
    if code == 0 and a.show_examples:
        print(report.render_examples(results, home))
    return code


if __name__ == "__main__":
    sys.exit(main())
