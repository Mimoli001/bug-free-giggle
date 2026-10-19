#!/usr/bin/env bash
# Persistent web-terminal session on a GitHub-hosted runner.
# Usage: bash terminal.sh restore | boot | hold | final | save | client
# Runs as the normal runner user; `sudo` is used only for short, bounded privileged commands.
set -euo pipefail

SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"
STATE_DIR="${STATE_DIR:-/mnt/state}"           # host dir, bind-mounted into the container
TAG="${STATE_TAG:-terminal-state}"              # rolling release that stores encrypted snapshots
REPO="${GITHUB_REPOSITORY:?}"
WORK="${RUNNER_TEMP:-/tmp}/state-work"
IMAGE="${DEV_IMAGE:-mcr.microsoft.com/devcontainers/universal:linux}"
CNAME=dev
CUSER=codespace
TTYD_PORT=7690                                   # not 7681: avoids the distro ttyd service
KEEP=2                                           # complete snapshots to keep
CHUNK=1900M                                      # release assets are limited to 2 GiB
SAVE_EVERY="${SAVE_EVERY:-180}"                  # autosave interval (seconds); unchanged state is skipped, so this is cheap
SESSION_SECONDS="${SESSION_SECONDS:-20100}"      # 5h35m, leaves room before the 6h cap
UPLOAD_TIMEOUT="${UPLOAD_TIMEOUT:-170}"          # per upload command; GitHub force-kills everything 5 min after Cancel
LANG_ENV="C.UTF-8"
# Heavy, regenerable directories are not worth snapshotting (override: STATE_EXCLUDES="" to keep everything)
STATE_EXCLUDES="${STATE_EXCLUDES-node_modules .venv __pycache__ .next .cache}"

mkdir -p "$WORK"
enc() { openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass env:STATE_PASSPHRASE "$@"; }
dec() { enc -d "$@"; }
log() { echo "[terminal] $*"; }
need() { command -v "$1" >/dev/null || { $SUDO apt-get update -qq && DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq "$2"; }; }
notify() {  # optional Telegram message (keeps the URL out of public logs)
  [ -n "${TG_BOT_TOKEN:-}" ] && [ -n "${TG_CHAT_ID:-}" ] || return 0
  curl -fsS -m 15 "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
    --data-urlencode "chat_id=$TG_CHAT_ID" --data-urlencode "text=$1" >/dev/null || true
}
assets() { gh release view "$TAG" -R "$REPO" --json assets -q '.assets[].name' 2>/dev/null || true; }
fingerprint() { $SUDO find "$STATE_DIR" -type f -printf '%P\0%s\0%T@\0' 2>/dev/null | sha256sum | cut -d' ' -f1; }

# ---------------------------------------------------------------- restore
restore() {
  : "${STATE_PASSPHRASE:?}"; need zstd zstd
  $SUDO rm -f "$STATE_DIR.restored"; $SUDO mkdir -p "$STATE_DIR"
  local stamps ts ok=0
  stamps=$(assets | sed -n 's/^state-\([0-9]\+\)\.done$/\1/p' | sort -rn)
  if [ -z "$stamps" ]; then
    log "no snapshot found: first run"
  else
    for ts in $stamps; do
      log "trying snapshot $ts"
      $SUDO find "$STATE_DIR" -mindepth 1 -delete
      rm -rf "$WORK/dl"; mkdir -p "$WORK/dl"
      if gh release download "$TAG" -R "$REPO" -D "$WORK/dl" --pattern "state-$ts.enc.*" \
         && cat "$WORK"/dl/state-"$ts".enc.* | dec | zstd -d | $SUDO tar -x -C "$STATE_DIR"; then
        ok=1; log "restored snapshot $ts"; break
      fi
      log "snapshot $ts failed, trying older"
    done
    rm -rf "$WORK/dl"
    [ "$ok" = 1 ] || { log "ERROR: no snapshot could be restored (wrong STATE_PASSPHRASE?)"; exit 1; }
  fi
  $SUDO mkdir -p "$STATE_DIR"/{workspaces,persist,opencode/share,opencode/config,opencode/state}
  $SUDO chown -R 1000:1000 "$STATE_DIR"
  fingerprint > "$WORK/last.fp"
  $SUDO touch "$STATE_DIR.restored"      # saving is refused until this exists (never clobber a good snapshot)
}

# ---------------------------------------------------------------- save
sqlite_backup() {   # consistent copy of a live SQLite file; bounded in time, raw-copy fallback
  local src="$1" dst="$2"
  if $SUDO timeout 60 python3 - "$src" "$dst" <<'PY'
import sqlite3, sys
src = sqlite3.connect(sys.argv[1], timeout=20); dst = sqlite3.connect(sys.argv[2])
src.backup(dst, pages=4000, sleep=0.05); dst.close(); src.close()
PY
  then $SUDO chown "$(id -u):$(id -g)" "$dst"; return 0; fi
  log "sqlite backup of $src failed or timed out: falling back to raw copy"
  local e; $SUDO cp -a "$src" "$dst"
  for e in -wal -shm; do [ -f "$src$e" ] && $SUDO cp -a "$src$e" "$dst$e" || true; done
  $SUDO chown -R "$(id -u):$(id -g)" "$dst"* || true
}

_save_locked() {
  local T0 ts snap fp x; T0=$(date +%s); ts=$T0; snap="$WORK/snap"
  fp=$(fingerprint)
  if [ -z "${FORCE_SAVE:-}" ] && [ -f "$WORK/last.fp" ] && [ "$fp" = "$(cat "$WORK/last.fp")" ]; then
    log "no changes since last save: skipped"; return 0
  fi
  rm -rf "$WORK/out" "$snap"; mkdir -p "$WORK/out" "$snap"
  local ex=(--exclude='*.db' --exclude='*.db-wal' --exclude='*.db-shm' --exclude='.save-now')
  for x in $STATE_EXCLUDES; do ex+=(--exclude="$x"); done
  # 1) everything except live SQLite files (tar exit 1 = a file changed while reading: acceptable)
  $SUDO tar -C "$STATE_DIR" "${ex[@]}" -cf - . | tar -C "$snap" -xf - || [ $? -eq 1 ]
  # 2) SQLite files (opencode sessions) through the online-backup API
  while IFS= read -r -d '' db; do
    local rel="${db#"$STATE_DIR"/}"; mkdir -p "$snap/$(dirname "$rel")"
    sqlite_backup "$db" "$snap/$rel"
  done < <($SUDO find "$STATE_DIR" -type f -name '*.db' -print0)
  log "staged $(du -sh "$snap" | cut -f1) in $(( $(date +%s) - T0 ))s"
  # 3) tar -> zstd -> AES-256 -> <2 GiB chunks
  tar -C "$snap" -cf - . | zstd -T0 -3 -q | enc | split -b "$CHUNK" -d -a 3 - "$WORK/out/state-$ts.enc."
  ( cd "$WORK/out" && sha256sum state-"$ts".enc.* > "state-$ts.done" )
  log "packed $(du -ch "$WORK"/out/state-"$ts".enc.* | tail -1 | cut -f1) in $(( $(date +%s) - T0 ))s"
  # 4) chunks first, the .done marker last => a half-uploaded snapshot is never used
  gh release view "$TAG" -R "$REPO" >/dev/null 2>&1 || \
    gh release create "$TAG" -R "$REPO" --title "terminal state (encrypted)" \
      --notes "Auto-managed encrypted snapshots. Do not edit." --latest=false
  timeout --foreground "$UPLOAD_TIMEOUT" gh release upload "$TAG" -R "$REPO" --clobber "$WORK"/out/state-"$ts".enc.*
  timeout --foreground 60 gh release upload "$TAG" -R "$REPO" --clobber "$WORK/out/state-$ts.done"
  echo "$fp" > "$WORK/last.fp"
  # 5) retention: keep the newest $KEEP complete snapshots
  local keep_ts a t; keep_ts=$(assets | sed -n 's/^state-\([0-9]\+\)\.done$/\1/p' | sort -rn | head -n "$KEEP")
  for a in $(assets); do
    t=$(echo "$a" | sed -n 's/^state-\([0-9]\+\)\..*/\1/p')
    echo "$keep_ts" | grep -qx "$t" || timeout --foreground 30 gh release delete-asset "$TAG" "$a" -R "$REPO" -y || true
  done
  rm -rf "$WORK/out" "$snap"
  log "saved snapshot $ts in $(( $(date +%s) - T0 ))s"
}

# Lock = a directory owned by a PID. No file descriptors involved, so no child process can ever keep it
# alive by accident, and a lock whose owner is dead is simply taken over.
lock_acquire() {
  local lock="$WORK/state.lock.d" waited=0 owner
  while ! mkdir "$lock" 2>/dev/null; do
    owner=$(cat "$lock/pid" 2>/dev/null || true)
    if [ -n "$owner" ] && ! kill -0 "$owner" 2>/dev/null; then rm -rf "$lock"; continue; fi   # stale
    [ "$waited" -ge "${LOCK_WAIT:-90}" ] && return 1
    sleep 1; waited=$((waited + 1))
  done
  echo "$BASHPID" > "$lock/pid"
}

save() {
  : "${STATE_PASSPHRASE:?}"
  [ -f "$STATE_DIR.restored" ] || { log "refusing to save: state was never restored"; return 1; }
  (
    if lock_acquire; then trap 'rm -rf "$WORK/state.lock.d"' EXIT
    elif [ -n "${SAVE_ANYWAY:-}" ]; then log "lock busy: saving anyway"
    else log "another save still holds the lock after ${LOCK_WAIT:-90}s"; exit 1; fi
    _save_locked
  )
}

# ---------------------------------------------------------------- client (custom web UI: Persian/RTL, paste, Vazirmatn)
build_client() {
  local here d="$WORK/clientbuild"; here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  rm -rf "$d"; mkdir -p "$d"
  ( cd "$d" && npm init -y >/dev/null && \
    npm i --silent --no-audit --no-fund @xterm/xterm@6.0.0 @xterm/addon-fit@0.11.0 vazirmatn@33.0.3 )
  python3 "$here/build_client.py" "$d/node_modules" "$here/client.template.html" "$WORK/client.html"
}

install_ttyd() {
  # Static binary on purpose: the Ubuntu `ttyd` package also installs+starts a systemd service
  # (read-only, no -W) that grabs port 7681 and swallows all keyboard input.
  if ! command -v ttyd >/dev/null; then
    $SUDO curl -fsSL -o /usr/local/bin/ttyd https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.x86_64 \
      && $SUDO chmod +x /usr/local/bin/ttyd || { need ttyd ttyd; }
  fi
  $SUDO systemctl disable --now ttyd >/dev/null 2>&1 || true
  $SUDO systemctl mask ttyd >/dev/null 2>&1 || true
  ttyd --version
}

# ---------------------------------------------------------------- boot
boot() {
  log "starting container $IMAGE"
  docker rm -f $CNAME >/dev/null 2>&1 || true
  docker run -d --name $CNAME --init \
    -v "$STATE_DIR/workspaces:/workspaces" \
    -v "$STATE_DIR/persist:/persist" \
    -v "$STATE_DIR/opencode/share:/home/$CUSER/.local/share/opencode" \
    -v "$STATE_DIR/opencode/config:/home/$CUSER/.config/opencode" \
    -v "$STATE_DIR/opencode/state:/home/$CUSER/.local/state/opencode" \
    -e LANG=$LANG_ENV -e LC_ALL=$LANG_ENV -e COLORTERM=truecolor \
    -e HISTFILE=/persist/.bash_history -e PROMPT_COMMAND='history -a' \
    -e GIT_CONFIG_GLOBAL=/persist/.gitconfig \
    "$IMAGE" sleep infinity
  local sh='bash -lc'
  docker exec -u root -e DEBIAN_FRONTEND=noninteractive $CNAME $sh 'command -v tmux >/dev/null || (apt-get update -qq && apt-get install -y -qq tmux)'
  # NOTE: the npm package is `opencode-ai` (there is no @opencode/cli). V2 beta = @opencode-ai/cli@next (separate session tables) - not used here.
  docker exec -u $CUSER -e OV="${OPENCODE_VERSION:-latest}" $CNAME $sh 'npm install -g --allow-scripts=opencode-ai "opencode-ai@$OV" || sudo env "PATH=$PATH" npm install -g --allow-scripts=opencode-ai "opencode-ai@$OV"; opencode --version'
  [ -n "${GIT_NAME:-}" ]  && docker exec -u $CUSER $CNAME git config --global user.name  "$GIT_NAME"
  [ -n "${GIT_EMAIL:-}" ] && docker exec -u $CUSER $CNAME git config --global user.email "$GIT_EMAIL"
  if [ -n "${GIT_PAT:-}" ]; then
    docker exec -u $CUSER -e P="$GIT_PAT" $CNAME bash -c \
      'umask 077; echo "https://x-access-token:$P@github.com" > /persist/.git-credentials; git config --global credential.helper "store --file /persist/.git-credentials"'
  fi
  if [ -n "${CLONE:-}" ] && [ -z "$($SUDO ls -A "$STATE_DIR/workspaces")" ]; then
    docker exec -u $CUSER $CNAME bash -c "cd /workspaces && git clone https://github.com/${CLONE}.git"
  fi
  # user hook: put `npm i -g ...`, `pip install ...`, `sudo apt-get install ...` in /persist/bootstrap.sh
  docker exec -u $CUSER $CNAME $sh '[ -f /persist/bootstrap.sh ] && bash /persist/bootstrap.sh || true'

  # web terminal: ttyd (custom RTL-aware client) -> tmux inside the container
  install_ttyd
  local idx=()
  if build_client; then idx=(-I "$WORK/client.html"); else log "WARNING: custom client build failed, using stock ttyd UI"; fi
  local auth=()
  [ -n "${TTYD_PASS:-}" ] && auth=(-c "${TTYD_USER:-dev}:$TTYD_PASS")
  nohup ttyd -W -i lo -p "$TTYD_PORT" "${auth[@]}" "${idx[@]}" \
    docker exec -it -u $CUSER -w /workspaces -e TERM=xterm-256color $CNAME bash -lc \
    'tmux -u new -A -s main \; set -g status off \; set -g set-clipboard on \; set -g history-limit 50000 \; set -g escape-time 10 || exec bash -l' \
    >"$WORK/ttyd.log" 2>&1 &
  local code=000
  for _ in $(seq 20); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$TTYD_PORT/" || true)
    case "$code" in 200|401) break;; esac; sleep 1
  done
  case "$code" in
    200|401) log "ttyd is up (HTTP $code, auth: $([ ${#auth[@]} -gt 0 ] && echo on || echo OFF))";;
    *) log "ERROR: ttyd is not healthy (HTTP $code)"; cat "$WORK/ttyd.log"; $SUDO ss -ltnp | grep ":$TTYD_PORT" || true; exit 1;;
  esac
  # tunnel
  if ! command -v cloudflared >/dev/null; then
    curl -fsSL -o "$WORK/cf.deb" https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
    $SUDO dpkg -i "$WORK/cf.deb" >/dev/null
  fi
  if [ -n "${CF_TUNNEL_TOKEN:-}" ]; then
    nohup cloudflared tunnel --no-autoupdate run --token "$CF_TUNNEL_TOKEN" >"$WORK/cf.log" 2>&1 &
    log "named tunnel started (use your fixed hostname)"
  else
    nohup cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:$TTYD_PORT" >"$WORK/cf.log" 2>&1 &
    local url=""
    for _ in $(seq 40); do
      url=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$WORK/cf.log" | head -1 || true)
      [ -n "$url" ] && break; sleep 2
    done
    if [ -n "${TG_BOT_TOKEN:-}" ] && [ -n "${TG_CHAT_ID:-}" ]; then
      notify "Terminal ready: ${url:-<URL not ready, see Actions log>}"
      log "terminal URL sent to Telegram (not printed here)"
    else
      log "terminal URL: ${url:-<not ready, see cf.log>}"
      echo "### Terminal: ${url:-pending}" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
    fi
  fi
}

# ---------------------------------------------------------------- final / hold
final() {   # usage: final [fromhold]
  if [ "${1:-}" != fromhold ]; then   # kill leftovers of a cancelled hold step so nothing can hold the lock
    pkill -f 'terminal\.sh hold' 2>/dev/null || true
    pkill -f 'terminal\.sh save' 2>/dev/null || true
  fi
  log "final: stopping container, then saving"
  timeout 30 docker stop -t 15 $CNAME >/dev/null 2>&1 || docker kill $CNAME >/dev/null 2>&1 || true
  LOCK_WAIT=20 SAVE_ANYWAY=1 FORCE_SAVE=1 save
}

hold() {
  local deadline=$(( ${JOB_START:?} + SESSION_SECONDS )) last spid="" stop=0
  last=$(date +%s)
  # Cancel => SIGINT/SIGTERM straight to this process (the workflow uses `exec`): leave quickly,
  # the always() "final" step does the save.
  trap 'stop=1; [ -n "$spid" ] && kill -TERM -- "-$spid" 2>/dev/null || true' INT TERM
  log "session open for $(( (deadline - $(date +%s)) / 60 )) more minutes (until $(date -u -d "@$deadline" +%H:%M) UTC)"
  while [ "$stop" = 0 ] && [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 5 & wait $! || true
    [ "$stop" = 0 ] || break
    local want=0
    if [ -e "$STATE_DIR/workspaces/.save-now" ]; then $SUDO rm -f "$STATE_DIR/workspaces/.save-now"; want=1   # in the terminal: touch /workspaces/.save-now
    elif [ $(( $(date +%s) - last )) -ge "$SAVE_EVERY" ]; then want=1; fi
    if [ "$want" = 1 ]; then
      setsid bash "$0" save & spid=$!        # own process group, so Cancel can kill the whole save pipeline
      wait "$spid" || log "autosave did not finish (will retry)"
      spid=""; last=$(date +%s)
    fi
  done
  if [ "$stop" = 1 ]; then log "stop requested: the final step will save"; exit 0; fi
  final fromhold
  notify "Session reached its time limit: state saved, a new run is starting."
  echo "saved=true"  >> "$GITHUB_OUTPUT"
  echo "chain=true"  >> "$GITHUB_OUTPUT"
}

case "${1:-}" in
  restore) restore;; boot) boot;; hold) hold;; final) final;; save) save;; client) build_client;;
  *) echo "usage: terminal.sh restore|boot|hold|final|save|client" >&2; exit 2;;
esac
