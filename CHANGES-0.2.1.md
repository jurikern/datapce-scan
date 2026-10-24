# datapce-scan 0.2.1: changes

## Privacy

- allow-suggest and allow-audit: a long flag prints only if it is on a short common list
  or on the public flag list of its program. Every other long flag prints as `<w>`.
  Before, any lowercase long flag printed, so a private word could show
  (`Bash(./deploy --acmecorp-prod)` printed `--acmecorp-prod`). One-letter flags print
  as before.
- secret-touch: a private file name under `~/.ssh` or `~/.gnupg` prints as an index id
  (`key file #1`, `secret-shaped file #2`). Before, it printed as a short hash of the
  name, and a dictionary search can find the name from that hash.

## secret-touch counts

- `tee F`, `sed -i F` and the target of `cp` and `mv` now count as writes. Before, they
  counted as reads (`mv`: not counted). `sed -i F` also still counts as a read, because
  sed reads the file before it writes it back. `cp` still counts its other words as reads. A
  target directory (from `-t`, a trailing `/`, or two or more sources) counts as written,
  and so does each source name in it. `cp -S SUFFIX` and `--suffix` take a value, also in
  a short group such as `-fS .bak`.
- `cp .env .env` counts as a write only. Before, it counted as a read. cp refuses to copy
  a file onto itself, so it reads no file, and the old read was a false positive.
- A command of assignments only keeps its redirect: `X=1 > .env` writes `.env`.
- allow-suggest: a command of assignments only (`PATH=/x`) now counts. This count can
  only go up.
- One call can count a read and a write of the same file.
- `<&file` no longer counts as a read. Bash and zsh reject it (bash: "ambiguous
  redirect"; zsh: "file number expected"), so it opens no file.
- The values table has a new column: the input placeholder-like count per kind. In TSV
  output it is the last field of each `value` row, so the earlier fields keep their
  places.

## allow-audit flags

- A wildcard in the program word no longer hides the program: `Bash(rm*)` gets the
  destructive flag, `Bash(xargs*)` the runner flag.
- `cp`, `tee` and `install` rules get the destructive flag. `sed`, `awk`, `sort`, `tar`
  and `perl` rules with a wildcard get it too (`sed -i`, `awk` `system()`, `sort -o`,
  `tar -x`), and so does an exact `sed -i` rule.
- A wildcard in or right after a subcommand with a destructive form below it gets the
  destructive flag: `git worktree*`, `git branch -D *`, `git stash *`, `aws s3 *`,
  `docker compose *`, `gh pr *` and similar. `tmux new-session *` and `git submodule *`
  get the runner flag.
- Expect more flagged rules after the upgrade. No flag was removed.

## Redirects to standard streams

- `> /dev/stdout`, `> /dev/stderr`, `> /dev/stdin` and `> /dev/fd/N` no longer count as
  file writes. They name a file descriptor, not a file. `/dev/tty` and other paths still
  count.
- Effect in allow-audit: a guard deny on such a past call now counts as likely-false, not
  as destructive, when the program is read-only and nothing else in the call writes. The
  guard replay text still holds the redirect, so the deny itself is still found.
- Effect in allow-suggest: such a call is no longer permission-relevant because of the
  redirect alone.
