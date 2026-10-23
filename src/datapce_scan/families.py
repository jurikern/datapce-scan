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
# Fix round 2 (item A): a rule word prints only if it has one of these shapes. Each shown word
# is a fixed public name from the lists below, a flag with no value, or `*`. Every other word
# is hidden. A list here can only make output less readable, never leak a private word.

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
HIDDEN = "<w>"


def is_flag(word: str) -> bool:
    """A flag with no value: -x, or --long-name (no `=`, no attached value)."""
    return bool(_FLAG_SHORT.match(word) or _FLAG_LONG.match(word))


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
    subcommand from SUBCOMMANDS, then one from SUBSUB; after that only flags and `*`. A shell
    operator word starts a new program position."""
    out, pos, prog, sub = [], 0, "", ""
    for w in words:
        ok = False
        if w in OPERATORS:
            out.append(True)
            pos, prog, sub = 0, "", ""
            continue
        if w == "*" or is_flag(w):
            ok = True
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
