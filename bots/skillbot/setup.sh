#!/usr/bin/env bash
# One-time skillbot host setup, run by hand from your admin machine. Idempotent. On the machine that
# runs the bot (the collector):
#   ssh-keygen -t ed25519 -N '' -C skillbot@collector -f ~/.ssh/id_ed25519_skillbot
# then run `SKILLBOT_PUBKEY="$(cat ~/.ssh/id_ed25519_skillbot.pub)" ./setup.sh hostb hostc`. It installs
# collect.sh as ~/.local/lib/skillbot/collect.sh on each named remote host and adds ONE authorized_keys
# line to each: restrict, from=<collector address>, collect.sh forced. (The collecting host runs the
# collector locally and needs nothing.) Each authorized_keys is backed up first.
set -euo pipefail
cd "$(dirname "$0")"
PUB="${SKILLBOT_PUBKEY:?set SKILLBOT_PUBKEY to the contents of the collector public key file}"
FROM="${SKILLBOT_FROM:-198.51.100.10}"  # the collector's address as the remote host sees it: change it
[ "$#" -gt 0 ] || { echo "usage: $0 remote-host..." >&2; exit 2; }
entry() { printf 'restrict,from="%s",command="bash $HOME/.local/lib/skillbot/collect.sh" %s\n' "$FROM" "$PUB"; }
# one script on stdin of `bash -s` (a remote login shell may be fish, so nothing bash-only goes on the ssh line)
remote_script() {
  printf 'set -eu\nmkdir -p ~/.ssh ~/.local/lib/skillbot\nchmod 700 ~/.ssh\ntest -d ~/.ssh -a -w ~/.ssh\ncat > ~/.local/lib/skillbot/collect.sh <<'"'"'EOF_COLLECT'"'"'\n'
  cat collect.sh
  printf 'EOF_COLLECT\nchmod 644 ~/.local/lib/skillbot/collect.sh\nf=$HOME/.ssh/authorized_keys\n'
  # replace the entry carrying the key's comment (a rotated key or a changed from= must not leave the old one authorized);
  # the first backup is kept as the pristine original, and `cat >` rewrites the file in place so its mode stays
  # (grep exits 1 when nothing is left to keep, so it is `|| true`; the last line proves the entry landed)
  printf 'umask 077\n[ -e $f ] || : > $f\n[ -e $f.bak-skillbot ] || cp -p $f $f.bak-skillbot\n{ grep -vF %s $f || true; cat <<'"'"'EOF_KEY'"'"'\n%s\nEOF_KEY\n} > $f.new\ncat $f.new > $f; rm -f $f.new\ngrep -qF %s $f\n' "'${PUB##* }'" "$(entry)" "'${PUB##* }'"
}
for host in "$@"; do
  echo "== $host"
  remote_script | ssh "$host" 'bash -s'
done
