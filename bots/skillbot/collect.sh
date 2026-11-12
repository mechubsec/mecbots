#!/usr/bin/env bash
# skillbot inventory collector. Runs on each host (locally on the collecting host, through the restricted
# key `id_ed25519_skillbot` elsewhere). Read-only, no arguments, no network, never prints file
# contents. One tab-separated line per item:
#   claude|codex|hermes  name  version  sha256-of-SKILL.md      (version "-" when SKILL.md has none)
#   gstack               -     VERSION  git HEAD short sha       (the suite counts once, not per skill)
#   plugin               name  version  commit sha               (Claude plugins)
# Claude skills that are symlinks into the gstack checkout belong to the gstack line.
set -uo pipefail
export LC_ALL=C
GSTACK="$HOME/.claude/skills/gstack"

# top-level `version:` of the first frontmatter block, quotes stripped
version_of() {
  awk '/^---[ \t]*$/ { if (++fence == 2) exit; next }
       fence == 1 && /^version:/ { sub(/^version:[ \t]*/, ""); gsub(/["\047 \t\r]/, ""); print; exit }' "$1"
}

emit_skill() {  # harness skill_md_path name
  local harness="$1" file="$2" name="$3" version sha
  [ -f "$file" ] || return 0
  version=$(version_of "$file")
  sha=$(sha256sum "$file" | cut -d' ' -f1)
  printf '%s\t%s\t%s\t%s\n' "$harness" "$name" "${version:--}" "$sha"
}

if [ -d "$HOME/.claude/skills" ]; then
  for file in "$HOME"/.claude/skills/*/SKILL.md; do
    dir=$(dirname "$file")
    name=$(basename "$dir")
    [ "$name" = gstack ] && continue
    if [ -L "$file" ]; then
      case "$(readlink -f "$file")" in "$GSTACK"/*) continue ;; esac
    fi
    emit_skill claude "$file" "$name"
  done
fi

# Codex reads user skills from ~/.agents/skills and ships its own under ~/.codex/skills/.system
for file in "$HOME"/.agents/skills/*/SKILL.md "$HOME"/.codex/skills/*/SKILL.md "$HOME"/.codex/skills/.system/*/SKILL.md; do
  emit_skill codex "$file" "$(basename "$(dirname "$file")")"
done

# ~/.hermes/skills/<category>/<name>/SKILL.md; hidden dirs (.archive, .hub) are not in use
for file in "$HOME"/.hermes/skills/*/*/SKILL.md; do
  emit_skill hermes "$file" "$(basename "$(dirname "$file")")"
done

if [ -f "$GSTACK/VERSION" ]; then
  printf 'gstack\t-\t%s\t%s\n' "$(head -n1 "$GSTACK/VERSION" | tr -d ' \r')" "$(git -C "$GSTACK" rev-parse --short HEAD 2>/dev/null || echo -)"
fi

plugins="$HOME/.claude/plugins/installed_plugins.json"
if [ -f "$plugins" ] && command -v python3 >/dev/null 2>&1; then
  python3 -I - "$plugins" <<'PY'
import json, sys
for key, installs in json.load(open(sys.argv[1])).get("plugins", {}).items():
    for install in installs:
        print("plugin", key.split("@")[0], install.get("version") or "-", (install.get("gitCommitSha") or "-")[:12], sep="\t")
PY
fi

exit 0
