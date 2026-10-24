"""A public allow-list of common command names.

By default the summary prints a command family only if its name is on this list (after a
trailing version number is removed: python3.14 -> python). All other names are counted in one
"(other: N)" row, so a private script or tool name does not show.

Python 3.9+, stdlib only.
"""
import re

_SPECIAL = {"(none)", "(variable)", "(substitution)"}

_NAMES = """
. : [ [[ alias awk basename bash bg bind break builtin caffeinate cal case cat cd chgrp chmod
chown chroot cksum clear cmp column comm command compgen complete continue cp csplit csh curl
cut dash date dc dd declare df diff diff3 dig dirname dirs disown du echo egrep enable env eval
exec exit expand export expr factor false fc fg fgrep file find fish fmt fold free fuser
getopts grep groups gunzip gzip hash head help history host hostname iconv id install jobs
join jq kill killall ksh less let link ln local locale logname ls lsof make man md5 md5sum
mkdir mkfifo mknod mktemp more mount mv nc netstat nice nl nohup nproc nslookup od open
openssl paste patch pgrep pidof ping pkill popd pr printenv printf ps pushd pwd read readlink
readonly realpath renice return rev rg rm rmdir rsync scp sed seq set sh sha1sum sha256sum
shasum shift shopt shred shuf sleep sort source split ssh ssh-keygen stat stdbuf strings stty
su sudo sum sync tac tail tar tee test time timeout tmux top touch tr trap tree true truncate
tsort tty type typeset ulimit umask umount unalias uname unexpand uniq unlink unset unzip
until uptime users vi vim w wait watch wc wget whereis which while who whoami xargs xxd yes
zcat zip zsh nano emacs code pbcopy pbpaste osascript defaults launchctl sw_vers mdfind
plutil security xcrun xcodebuild brew port apt apt-get dpkg yum dnf rpm pacman snap
git gh hub git-lfs svn hg
python python3 pip pip3 pipx uv uvx poetry pdm hatch tox nox pytest ruff black isort mypy
pyright flake8 pylint conda mamba virtualenv ipython jupyter
node npm npx pnpm yarn bun bunx deno tsc tsx eslint prettier vitest jest next vite
ruby gem bundle bundler rake rails irb
go gofmt cargo rustc rustup rustfmt clippy-driver
java javac mvn gradle kotlin scala sbt
gcc g++ clang clang++ cc c++ ld cmake ninja meson pkg-config gdb lldb valgrind strace
docker docker-compose podman kubectl helm kind minikube k9s terraform tofu ansible
aws gcloud az linode-cli doctl flyctl vercel netlify heroku
sqlite3 psql mysql redis-cli mongosh duckdb
ffmpeg convert magick sips pandoc perl php lua R Rscript julia swift swiftc
ollama llama-server claude codex
""".split()

PUBLIC = frozenset(_NAMES) | frozenset(_SPECIAL)
_VERSION = re.compile(r"[0-9][0-9.]*$")


def is_public(name: str) -> bool:
    if name in PUBLIC:
        return True
    base = _VERSION.sub("", name).rstrip("-.")
    return bool(base) and base in PUBLIC


# ---------------------------------------------------------------- public word shapes
# A rule word prints only if it has one of these shapes. Each shown word is a fixed public
# name from the lists below, a one-letter flag, a long flag on the list for its program
# (LONG_FLAGS) or on the common list, or `*`. Every other word is hidden. A list here can only make output less readable, never leak a private word.

_FLAG_SHORT = re.compile(r"^-[A-Za-z]$")
_FLAG_LONG = re.compile(r"^--[a-z][a-z-]*$")
_PROG_VERSION = re.compile(r"^(?P<base>[A-Za-z][A-Za-z0-9+_-]*?)(?P<v>[0-9]{1,2}(?:\.[0-9]{1,2})?)$")
OPERATORS = frozenset({"&&", "||", "|", "|&", ";", "&"})


def _words(text: str) -> frozenset:
    return frozenset(text.split())


_PM = _words("""test run install ci uninstall view ls list outdated audit publish pack config
exec init update version start build link prune cache doctor whoami help x i add remove why
info dlx create""")
SUBCOMMANDS = {
    "git": _words("""status log diff show add commit push pull fetch merge rebase reset checkout
switch restore branch tag stash rm mv clone init remote config rev-parse ls-files ls-tree blame
grep describe show-ref merge-base count-objects check-ignore check-attr name-rev for-each-ref
var worktree submodule cherry-pick revert clean gc reflog bisect apply am format-patch shortlog
cat-file rev-list update-ref filter-branch notes archive lfs help version range-diff"""),
    "gh": _words("""pr issue run repo release workflow api auth gist search browse label secret
variable cache codespace project status extension alias config ssh-key gpg-key ruleset"""),
    "npm": _PM, "pnpm": _PM, "yarn": _PM, "bun": _PM,
    "pip": _words("install uninstall list show freeze check download wheel config cache index"),
    "pip3": _words("install uninstall list show freeze check download wheel config cache index"),
    "uv": _words("run pip sync lock add remove tool venv python init build publish tree version"),
    "cargo": _words("""build test run check clippy fmt doc new init add remove update install
uninstall publish bench clean tree metadata search"""),
    "go": _words("build test run vet fmt mod get install list env version clean generate doc tool work"),
    "docker": _words("""ps images logs version info run exec build pull push rm rmi stop start
restart compose system volume network inspect tag login logout cp kill"""),
    "kubectl": _words("""get describe logs apply delete exec run rollout config create edit patch
scale top port-forward version cluster-info explain"""),
    "brew": _words("""list info install uninstall upgrade update search outdated doctor services
cleanup tap config leaves deps uses"""),
    "tmux": _words("""ls list-sessions list-windows list-panes has-session new-session attach
kill-session kill-server send-keys capture-pane new-window split-window display-message"""),
    "ollama": _words("list ps show run pull push rm serve create stop"),
    "launchctl": _words("list load unload bootout bootstrap print kickstart"),
    "defaults": _words("read write delete domains"),
    "aws": _words("""s3 sts ec2 iam lambda logs configure cloudformation ecr eks dynamodb sqs sns
ssm secretsmanager rds route53 cloudwatch"""),
    "gcloud": _words("auth config compute container projects run functions storage iam components info"),
    "terraform": _words("""init plan apply destroy validate fmt show output state import providers
version workspace refresh"""),
    "tofu": _words("""init plan apply destroy validate fmt show output state import providers
version workspace refresh"""),
    "helm": _words("install upgrade uninstall list status template repo dependency lint package version"),
    "conda": _words("install list env create remove update info search run"),
    "poetry": _words("install add remove run build publish show lock update check env shell"),
    "claude": _words("mcp plugin config doctor update"),
    "security": _words("find-generic-password find-internet-password dump-keychain list-keychains"),
    "xcrun": _words("simctl xcodebuild"),
    "openssl": _words("enc rand req x509 genrsa rsa s_client dgst version"),
    "systemctl": _words("status start stop restart enable disable list-units"),
    "apt": _words("install remove update upgrade list search show"),
    "apt-get": _words("install remove update upgrade"),
    "deno": _words("run task test fmt lint compile install"),
    "swift": _words("build test run package"),
    "codex": _words("exec login"),
}
SUBSUB = {
    ("gh", "pr"): _words("""list view diff checks status create merge close reopen edit comment
review checkout ready"""),
    ("gh", "issue"): _words("list view status create close reopen edit comment"),
    ("gh", "run"): _words("list view watch rerun cancel download"),
    ("gh", "repo"): _words("view list clone create fork sync"),
    ("gh", "release"): _words("list view create download delete upload"),
    ("gh", "workflow"): _words("list view run enable disable"),
    ("gh", "auth"): _words("status login logout token refresh"),
    ("docker", "compose"): _words("ps up down logs build pull config ls restart stop start exec run"),
    ("kubectl", "rollout"): _words("status restart history undo"),
    ("kubectl", "config"): _words("view get-contexts current-context use-context"),
    ("npm", "config"): _words("get set list delete edit"),
    ("aws", "s3"): _words("ls cp mv rm sync mb rb"),
    ("aws", "sts"): _words("get-caller-identity get-session-token"),
    ("git", "stash"): _words("list show drop pop apply clear push"),
    ("git", "worktree"): _words("list add remove prune"),
    ("git", "remote"): _words("show add remove"),
}
# MCP servers whose names are public (published servers). Any other server name is hidden.
MCP_PUBLIC = _words("""github gitlab filesystem playwright puppeteer context7 sentry linear notion
slack memory fetch git sequential-thinking sequentialthinking brave-search google-drive gdrive
postgres sqlite time everything figma stripe supabase vercel cloudflare atlassian asana
firecrawl exa tavily perplexity ide""")
# Claude Code tool names (rule tool position). Any other tool word is hidden.
KNOWN_TOOLS = _words("""Bash PowerShell Read Edit Write MultiEdit NotebookEdit NotebookRead Glob
Grep LS WebFetch WebSearch Agent Task Monitor TodoWrite Skill SlashCommand ExitPlanMode
BashOutput KillShell ScheduleWakeup""")
# Long flags that may print. A long flag is a free word (--acmecorp-prod), so only names from
# public manuals print: the common list for every program, and a list per known program.
COMMON_LONG = _words("""--help --version --verbose --quiet --all --force --recursive --dry-run
--json --yes --color --no-color --debug --list""")
_PM_LONG = _words("""--save --save-dev --save-exact --global --production --depth --long
--silent --workspace --workspaces --frozen-lockfile --offline --prefer-offline --watch
--coverage --filter --recursive""")
_PIP_LONG = _words("""--upgrade --user --editable --requirement --no-deps --no-cache-dir
--break-system-packages --outdated --format --pre --index-url --target --uptodate
--not-required""")
_SHA_LONG = _words("--check --binary --text --algorithm --status --strict --warn --tag")
LONG_FLAGS = {
    "git": _words("""--oneline --stat --shortstat --numstat --name-only --name-status --short
--porcelain --graph --decorate --cached --staged --no-pager --abbrev-ref --show-toplevel
--show-current --show-prefix --git-dir --is-inside-work-tree --global --local --get --hard
--soft --mixed --force-with-lease --no-verify --amend --no-edit --rebase --ff-only --no-ff
--tags --prune --depth --format --pretty --reverse --follow --no-merges --merges --merged
--no-merged --contains --exit-code --patch --word-diff --ignored --untracked-files --others
--exclude-standard --remotes --set-upstream --unset --abort --continue --skip --quit
--signoff --allow-empty --cherry-pick --left-right --first-parent --topo-order --date-order
--date --since --until --author --committer --grep --max-count --no-color --relative
--full-name --full-history --ignore-case --heads --sort --points-at --no-renames
--find-renames --summary --raw --check --minimal --histogram --no-abbrev --abbrev --verify
--symbolic-full-name --keep-index --include-untracked --index --stdin --no-index --bare
--single-branch --recurse-submodules --init --remote --dirty --long --always"""),
    "gh": _words("""--json --limit --state --repo --web --jq --template --body --title --base
--head --draft --fill --squash --merge --rebase --delete-branch --watch --log --log-failed
--comments --label --assignee --author --search --branch --workflow --status --exit-status
--name-only --patch --required --interval --fail-fast --auto --admin --ref --hostname"""),
    "npm": _PM_LONG, "pnpm": _PM_LONG, "yarn": _PM_LONG, "bun": _PM_LONG,
    "pip": _PIP_LONG, "pip3": _PIP_LONG,
    "uv": _words("""--with --python --frozen --locked --no-dev --dev --all-extras --extra
--upgrade --project --directory --no-sync --system --group --all-groups --inexact"""),
    "cargo": _words("""--release --all-features --no-default-features --features --workspace
--locked --frozen --offline --bin --lib --tests --test --examples --all-targets --package
--message-format --nocapture --check"""),
    "docker": _words("""--rm --detach --interactive --tty --name --follow --tail --build
--no-cache --format --no-trunc --filter --since --timestamps --pull --platform --tag"""),
    "kubectl": _words("""--namespace --all-namespaces --output --selector --context --watch
--follow --tail --previous --show-labels --since --container"""),
    "brew": _words("--cask --formula --installed --versions --full-name --prefix --greedy"),
    "python": _words("--version --help"),
    "pytest": _words("""--tb --maxfail --lf --ff --exitfirst --collect-only --no-header
--capture --durations --cov --cov-report --showlocals --strict-markers --last-failed
--failed-first --deselect --ignore --co"""),
    "ruff": _words("--fix --check --diff --select --ignore --statistics --show-fixes --watch"),
    "black": _words("--check --diff --line-length --fast"),
    "mypy": _words("--strict --ignore-missing-imports --no-error-summary --pretty --install-types"),
    "ls": _words("""--long --almost-all --human-readable --sort --reverse --classify --directory
--inode --size --time --full-time --group-directories-first"""),
    "grep": _words("""--recursive --ignore-case --line-number --count --files-with-matches
--files-without-match --include --exclude --exclude-dir --invert-match --word-regexp
--fixed-strings --extended-regexp --perl-regexp --only-matching --no-filename
--with-filename --context --before-context --after-context --max-count --binary-files
--no-messages --null --text --line-regexp --dereference-recursive"""),
    "rg": _words("""--files --hidden --no-ignore --type --type-not --glob --iglob --line-number
--no-line-number --count --count-matches --files-with-matches --files-without-match
--ignore-case --smart-case --case-sensitive --fixed-strings --word-regexp --no-heading
--heading --context --before-context --after-context --multiline --max-count --max-depth
--follow --only-matching --vimgrep --sort --stats --type-list --no-filename --with-filename
--invert-match --null --trim --unrestricted --search-zip"""),
    "curl": _words("""--silent --show-error --fail --fail-with-body --location --head --insecure
--request --header --data --data-raw --data-binary --output --max-time --connect-timeout
--compressed --retry --include --get --user-agent --remote-name --create-dirs
--write-out --form --url --proxy --ipv4 --ipv6"""),
    "wget": _words("--quiet --output-document --continue --timeout --tries --spider --no-verbose"),
    "jq": _words("""--raw-output --compact-output --slurp --arg --argjson --sort-keys
--exit-status --null-input --raw-input --join-output --tab --indent --monochrome-output
--color-output --ascii-output"""),
    "sort": _words("""--numeric-sort --reverse --unique --human-numeric-sort --key
--field-separator --ignore-case --version-sort --stable --general-numeric-sort --month-sort
--random-sort --check --merge --zero-terminated"""),
    "head": _words("--lines --bytes --silent --zero-terminated"),
    "tail": _words("--lines --bytes --follow --retry --silent --zero-terminated --pid"),
    "wc": _words("--lines --words --bytes --chars --max-line-length"),
    "du": _words("--summarize --human-readable --max-depth --apparent-size --total --bytes"),
    "df": _words("--human-readable --inodes --local --total --print-type"),
    "cat": _words("--number --number-nonblank --show-all --show-ends --show-tabs --squeeze-blank"),
    "diff": _words("""--unified --recursive --brief --side-by-side --new-file --ignore-all-space
--ignore-space-change --ignore-case --ignore-blank-lines --report-identical-files --normal
--suppress-common-lines --text --strip-trailing-cr --minimal"""),
    "find": _words("--help --version"),
    "xargs": _words("--null --no-run-if-empty --max-args --max-procs --verbose"),
    "tar": _words("""--create --extract --list --gzip --bzip2 --xz --zstd --file --exclude
--directory --strip-components --verbose --to-stdout --totals"""),
    "rsync": _words("""--archive --verbose --delete --dry-run --progress --exclude --include
--compress --checksum --human-readable --itemize-changes --partial --update --stats
--times --perms --links --relative"""),
    "make": _words("--dry-run --jobs --directory --keep-going --always-make --silent --file"),
    "node": _words("""--version --help --check --test --inspect --inspect-brk --watch
--input-type --no-warnings --trace-warnings --enable-source-maps --expose-gc"""),
    "npx": _words("--yes --no --package --no-install --prefer-offline"),
    "tsc": _words("--build --watch --pretty --project"),
    "eslint": _words("--fix --ext --cache --max-warnings --quiet --format --no-eslintrc"),
    "prettier": _words("--check --write --list-different --ignore-unknown --cache"),
    "vitest": _words("--run --watch --coverage --reporter --bail --ui --update"),
    "jest": _words("--watch --coverage --ci --bail --silent --update-snapshot"),
    "go": _words("--help"),
    "terraform": _words("--help --version"),
    "helm": _words("""--namespace --all-namespaces --values --set --dry-run --debug --install
--wait --atomic --create-namespace --output --version --revision"""),
    "claude": _words("""--print --model --resume --continue --output-format --input-format
--verbose --max-turns --permission-mode --add-dir --settings --mcp-config --agents
--allowed-tools --disallowed-tools --append-system-prompt --session-id --debug"""),
    "ssh-keygen": _words("--help"),
    "tmux": _words("--help"),
    "date": _words("--utc --universal --date --reference --rfc-email"),
    "uname": _words("""--all --kernel-name --nodename --kernel-release --kernel-version
--machine --processor --hardware-platform --operating-system"""),
    "env": _words("--ignore-environment --unset --null --chdir"),
    "tree": _words("--dirsfirst --noreport --prune --gitignore --charset --du --sort"),
    "pgrep": _words("--full --list-full --list-name --newest --oldest --exact --count --euid"),
    "sha256sum": _SHA_LONG, "sha1sum": _SHA_LONG, "md5sum": _SHA_LONG, "shasum": _SHA_LONG,
    "cut": _words("--fields --delimiter --characters --bytes --complement --only-delimited"),
    "tr": _words("--delete --squeeze-repeats --complement --truncate-set1"),
    "seq": _words("--separator --equal-width --format"),
    "realpath": _words("--relative-to --relative-base --canonicalize-missing --no-symlinks"),
    "readlink": _words("--canonicalize --canonicalize-existing --canonicalize-missing --no-newline"),
    "stat": _words("--format --printf --dereference --terse --file-system"),
    "basename": _words("--suffix --multiple --zero"),
    "column": _words("--table --separator --output-separator"),
    "ollama": _words("--help --verbose --format"),
    "sed": _words("""--quiet --silent --expression --regexp-extended --in-place --null-data
--separate --unbuffered --posix --debug --sandbox --line-length --follow-symlinks"""),
    "awk": _words("--field-separator --assign --file --version"),
}
HIDDEN = "<w>"


def is_flag(word: str) -> bool:
    """A flag shape with no value: -x, or --long-name (no `=`, no attached value)."""
    return bool(_FLAG_SHORT.match(word) or _FLAG_LONG.match(word))


def _prog_key(prog: str) -> str:
    """The key of a program in LONG_FLAGS: the name as written, else with no version suffix."""
    prog = _one_star(prog)
    if prog in LONG_FLAGS:
        return prog
    m = _PROG_VERSION.match(prog)
    return m.group("base").rstrip("-.") if m else prog


def public_flag(word: str, prog: str = "") -> bool:
    """A flag that may print: -x (one letter), or a long flag on the public list of the
    program (LONG_FLAGS) or on the common list. Any other long flag can be a private word."""
    if _FLAG_SHORT.match(word):
        return True
    if not _FLAG_LONG.match(word):
        return False
    return word in COMMON_LONG or word in LONG_FLAGS.get(_prog_key(prog), ())


def public_program(word: str) -> bool:
    """A public program name as written, or one with a short version suffix (python3.14)."""
    if word in _NAMES_SET:
        return True
    m = _PROG_VERSION.match(word)
    return bool(m) and m.group("base").rstrip("-.") in _NAMES_SET


_NAMES_SET = frozenset(_NAMES)


def _one_star(word: str) -> str:
    return word[:-1] if word.endswith("*") and word.count("*") == 1 else word


def public_mask(words) -> list:
    """For each word of one rule or command: True if it may print. Positions: program, then a
    subcommand from SUBCOMMANDS, then one from SUBSUB; after that only public flags
    (public_flag) and `*`. A shell
    operator word starts a new program position."""
    out, pos, prog, sub = [], 0, "", ""
    for w in words:
        ok = False
        if w in OPERATORS:
            out.append(True)
            pos, prog, sub = 0, "", ""
            continue
        if w == "*":
            ok = True
        elif is_flag(w):
            ok = public_flag(w, prog)
        elif pos == 0:
            ok = public_program(_one_star(w))
        elif pos == 1:
            ok = _one_star(w) in SUBCOMMANDS.get(prog, ())
        elif pos == 2:
            ok = _one_star(w) in SUBSUB.get((prog, sub), ())
        out.append(ok)
        if pos == 0:
            prog = w if ok else ""
        elif pos == 1:
            sub = w if ok else ""
        pos += 1
    return out


def public_words(words) -> bool:
    """True if every word may print."""
    return all(public_mask(words))
