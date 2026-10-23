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
