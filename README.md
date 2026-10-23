# datapce-scan

Read-only, local, nothing sent, no command text printed.

`datapce-scan` counts what a coding agent ran, from the agent logs already on your disk. It also replays public block lists over your past commands and counts what each list would have denied. Nothing installs into the agent. The tool does not block, change or send anything.

Home: https://codeberg.org/datapce/datapce-scan

## Quick start

```
uvx datapce-scan
uvx datapce-scan replay --rules all
```

Until the package is on PyPI, run it from the repository:

```
uvx --from git+https://codeberg.org/datapce/datapce-scan.git datapce-scan
uvx --from git+https://codeberg.org/datapce/datapce-scan.git datapce-scan replay --rules all
```

From a local checkout: `uvx --from . datapce-scan`.

Python 3.9 or later. No dependencies outside the Python standard library.

## What it reads and what it prints

| Item | Value |
|---|---|
| Input | Claude Code transcripts: `~/.claude/projects/*/*.jsonl`. Subagent transcripts only with `--include-subagents`. |
| File access | Read only. The tool opens files in read mode and writes no file. |
| Network | None. The source has no network module. To make sure, run `grep -rnE "import (socket|urllib|http|ssl)" src/` (no result). |
| Output | Counts and labels only: tool names, command family (first word, public command names only), repo directory basename (or a hash with `--hash-repos`), UTC day. |
| Never printed | Command text, full paths, e-mail addresses, secrets. A last check stops the output if it holds an e-mail address or a home-directory path. |
| Formats | Table (default), `--json`, `--tsv`. |

## Commands

| Command | Result |
|---|---|
| `datapce-scan` | Calls by tool, Bash command family, repo and day; sessions; active hours. A family shows by name only if it is on a public list of common commands (`src/datapce_scan/families.py`); all other names go into one "other" row. |
| `datapce-scan replay --rules NAME` | For each rule set: denies, asks, denies per rule, denies per Bash hour, and the share of denies that are likely false. `NAME` is a packaged name, a comma list, `all`, or a path to your own rule-set JSON file. |
| `datapce-scan rules` | The packaged rule sets, with source, licence and fetch date. |

Common options: `--projects DIR`, `--include-subagents`, `--since YYYY-MM-DD`, `--until YYYY-MM-DD`, `--json`, `--tsv`.

### Show local family names (off by default)

WARNING: `--show-local-families` prints every command family name. The names can include private script or tool names. Do not share that output.

`datapce-scan --show-local-families` shows all family names. The output starts with a WARNING line.

### Show examples (off by default)

WARNING: `--show-examples` prints command text from your own logs. Do not share or paste that output. The tool masks e-mail addresses and secret-like values, but other private text can show.

`datapce-scan replay --rules sage --show-examples 3` prints up to 3 matched commands for each rule. It works only in the table format and only when the output goes to a terminal, not to a pipe or a file.

## Packaged rule sets

| Name | Rules | Source | Licence | Reuse |
|---|---|---|---|---|
| `datapce-6` | 6 | datapce guard v0 deny list, matcher defects fixed | own work | own |
| `datapce-6-v0` | 6 | the same list with the v0 prefix matcher, for comparison | own work | own |
| `cc-safety-net` | 28 | https://github.com/kenryu42/cc-safety-net (rm and git rules) | MIT | own paraphrase of the rule logic; rule ids kept |
| `sage` | 56 | https://github.com/gendigitalinc/sage/tree/main/threats (command rules) | DRL-1.1 | copied with rule author, link and licence |
| `cupcake-examples` | 8 | https://github.com/eqtylab/cupcake (Bash rules of 3 example policies) | Apache-2.0 | copied with attribution |

Each rule-set file records the source URL, the upstream commit, the licence and the fetch date (2026-10-22). See `src/datapce_scan/rules/NOTICE`.

## Measures

| Measure | Meaning |
|---|---|
| deny, ask | The first deny rule that matches a call, else the first ask rule. One verdict for each call. |
| Bash call | A tool call named Bash, with or without command text. The replay runs on the calls with command text. |
| Bash hour | A UTC clock hour with at least one Bash call. |
| active hour | A UTC clock hour with at least one tool call. |
| temp-dir target | Every path target of the matched command is in a temp directory (`/tmp`, `/private/tmp`, `/var/tmp`, `/var/folders`, `$TMPDIR`, or a `mktemp` result). For git, the target is the repo. A deny of this type is likely false. |
| heredoc text only | A text or regex rule matches only text inside a heredoc body (a file body or a script), not a command line. A deny of this type is likely false. |

How the matcher reads a command: a real shell tokenizer (`shlex`) splits the command. The matcher looks inside `bash -c`, `sh -c`, `eval`, `$( )`, backticks, `<( )` and `find -exec`. It removes `sudo`, `env`, `nohup`, `timeout`, `xargs` and similar wrappers. `rm -fr`, `rm -rf` and `rm -r -f` are the same. `/` is the root directory only, not every absolute path. Text and regex rules from public lists (Sage, Cupcake) run on the whole command text, as the source tools do.

## Sample output (synthetic data)

```
datapce-scan 0.1.0 | read-only, local, nothing sent, no command text printed

Source: Claude Code transcripts, 3 files, 2026-10-20 to 2026-10-21 (UTC), subagents not included

Totals
  tool calls                                       9
  Bash calls                                       7
  simple commands in Bash calls                    9
  sessions                                         3
  active hours (UTC clock hours with a tool call)  3
  days                                             2

Tools  [calls, share]
  Bash  7  77.8%
  Edit  1  11.1%
  Read  1  11.1%

Bash command families (first word)  [calls, share]
  git         3  33.3%
  rm          2  22.2%
  bash        1  11.1%
  cd          1  11.1%
  curl        1  11.1%
  (other: 1)  1  11.1%
```

```
datapce-scan 0.1.0 | read-only, local, nothing sent, no command text printed
Replay: what each rule set would have done to past Bash calls. Nothing was blocked; this is a count.

Rule set: datapce-6  (6 rules; licence own work (datapce); datapce guard v0; fetched 2026-10-22)
  Bash calls                                                 7
  Bash hours (UTC clock hours with a Bash call)              3
  denies                                                     2
  asks                                                       0
  denies per Bash hour                                   0.667
  denies with a temp-dir target (likely false)        0 (0.0%)
  denies that match heredoc text only (likely false)  0 (0.0%)
  denies by rule  [denies, temp-dir target, heredoc text only]
    git-push-force  1  0  0
    rm-rf-root      1  0  0
```

## Limits

1. Claude Code logs only. Codex and other agents are not read in v0.
2. A replay is a count from text. It does not run commands and does not know what a command did.
3. The `cc-safety-net` set is a paraphrase. It does not model secret-file rules, pipe-to-shell, the temp-repo and worktree relaxations, or rulebook packs. Its counts can differ from the real tool.
4. The `sage` set does not model trusted-domain suppression, URL checks or package checks. Actions use the Sage default "balanced" thresholds.
5. The `cupcake-examples` set holds example policies, not Cupcake defaults.
6. The shell parser does not expand variables, aliases or functions. It follows a variable only when the same call sets it to a literal value or to a `mktemp` result. A quoted operator (for example `";"`) splits a command.
7. "Temp-dir target" and "heredoc text only" mark likely false denies. They are not a full count of false denies.
8. A command family is the basename of the first word. Names that are not on the public list are counted, but not named, unless you use `--show-local-families`.
9. Times are UTC.

## Development

```
python3 -m unittest discover -s tests -t .
```

The tests use synthetic transcripts only. CI: `.forgejo/workflows/test.yml` runs the suite on Python 3.9 and 3.13 (NOT MEASURED: not run until the first push).

## Licence

MIT, see `LICENSE`. The third-party rule data keeps its own licences (MIT, Apache-2.0, DRL-1.1); see `src/datapce_scan/rules/NOTICE`.
