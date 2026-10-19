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
TTYD_PORT=7690                                   # public port (nginx front); not 7681: avoids the distro ttyd service
TTYD_SLOT_BASE=7691                              # ttyd slot i listens on TTYD_SLOT_BASE+i-1 (loopback only)
TERM_SLOTS="${TERM_SLOTS:-6}"                    # independent terminals offered by the UI (1..12)
KEEP=3                                           # complete snapshots to keep (deeper fallback if the newest is damaged)
CHUNK=1900M                                      # release assets are limited to 2 GiB
SAVE_EVERY="${SAVE_EVERY:-180}"                  # autosave interval (seconds); unchanged state is skipped, so this is cheap
SESSION_SECONDS="${SESSION_SECONDS:-20100}"      # 5h35m, leaves room before the 6h cap
UPLOAD_TIMEOUT="${UPLOAD_TIMEOUT:-170}"          # per upload command; GitHub force-kills everything 5 min after Cancel
LANG_ENV="C.UTF-8"
# Heavy, regenerable directories are not worth snapshotting (override: STATE_EXCLUDES="" to keep everything)
STATE_EXCLUDES="${STATE_EXCLUDES-node_modules .venv __pycache__ .next .cache}"
case "$TERM_SLOTS" in ''|*[!0-9]*) TERM_SLOTS=6;; esac
[ "$TERM_SLOTS" -ge 1 ] && [ "$TERM_SLOTS" -le 12 ] || TERM_SLOTS=6

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
    log "restore: no snapshot found — this is a first run (nothing to restore)"
  else
    for ts in $stamps; do
      log "restore: trying snapshot $ts"
      $SUDO find "$STATE_DIR" -mindepth 1 -delete
      rm -rf "$WORK/dl"; mkdir -p "$WORK/dl"
      # download chunks + the .done manifest (holds sha256 sums), verify checksums BEFORE decrypting:
      # a damaged or half-uploaded snapshot is rejected here and we fall back to an older one.
      if gh release download "$TAG" -R "$REPO" -D "$WORK/dl" --pattern "state-$ts.enc.*" \
         && gh release download "$TAG" -R "$REPO" -D "$WORK/dl" --pattern "state-$ts.done" \
         && ( cd "$WORK/dl" && sha256sum -c "state-$ts.done" ) \
         && cat "$WORK"/dl/state-"$ts".enc.* | dec | zstd -d | $SUDO tar -x -C "$STATE_DIR"; then
        ok=1; log "RESTORE SUCCESS: snapshot $ts restored (sha256 verified)"; break
      fi
      log "restore: snapshot $ts failed — trying older"
    done
    rm -rf "$WORK/dl"
    [ "$ok" = 1 ] || { log "RESTORE FAILED: no snapshot could be restored (wrong STATE_PASSPHRASE?)"; echo "::error title=Restore failed::no snapshot could be restored — check STATE_PASSPHRASE"; exit 1; }
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
  local T0 ts snap out fp x a t keep_ts have want missing nchunks size
  T0=$(date +%s); ts=$T0
  snap="$WORK/snap.$$"; out="$WORK/out.$$"   # per-PID paths: a final save can never collide with an autosave
  fp=$(fingerprint)
  if [ -z "${FORCE_SAVE:-}" ] && [ -f "$WORK/last.fp" ] && [ "$fp" = "$(cat "$WORK/last.fp")" ]; then
    log "save check: no changes since the last snapshot — nothing to upload (OK)"; return 0
  fi
  rm -rf "$snap" "$out"; mkdir -p "$out" "$snap"
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
  tar -C "$snap" -cf - . | zstd -T0 -3 -q | enc | split -b "$CHUNK" -d -a 3 - "$out/state-$ts.enc."
  ( cd "$out" && sha256sum state-"$ts".enc.* > "state-$ts.done" )
  log "packed $(du -ch "$out"/state-"$ts".enc.* | tail -1 | cut -f1) in $(( $(date +%s) - T0 ))s"
  # 4) chunks first, the .done marker last => a half-uploaded snapshot is never used
  gh release view "$TAG" -R "$REPO" >/dev/null 2>&1 || \
    gh release create "$TAG" -R "$REPO" --title "terminal state (encrypted)" \
      --notes "Auto-managed encrypted snapshots. Do not edit." --latest=false >/dev/null
  timeout --foreground "$UPLOAD_TIMEOUT" gh release upload "$TAG" -R "$REPO" --clobber "$out"/state-"$ts".enc.*
  timeout --foreground 60 gh release upload "$TAG" -R "$REPO" --clobber "$out/state-$ts.done"
  # 5) verify every uploaded asset really exists in the release before calling it a success
  have=$(assets)
  for a in "$out"/state-"$ts".*; do
    want=$(basename "$a")
    echo "$have" | grep -qx "$want" || { log "save verify: asset $want is missing after upload"; missing=1; }
  done
  [ "${missing:-0}" = 0 ] || return 1
  echo "$fp" > "$WORK/last.fp"     # only after a verified upload, so a failure is retried on the next autosave
  # 6) retention: keep the newest $KEEP complete snapshots
  keep_ts=$(assets | sed -n 's/^state-\([0-9]\+\)\.done$/\1/p' | sort -rn | head -n "$KEEP")
  for a in $(assets); do
    t=$(echo "$a" | sed -n 's/^state-\([0-9]\+\)\..*/\1/p')
    echo "$keep_ts" | grep -qx "$t" || timeout --foreground 30 gh release delete-asset "$TAG" "$a" -R "$REPO" -y || true
  done
  nchunks=$(ls "$out"/state-"$ts".enc.* | wc -l | tr -d ' '); size=$(du -ch "$out"/state-"$ts".enc.* | tail -1 | cut -f1)
  rm -rf "$out" "$snap"
  log "SAVE SUCCESS: snapshot $ts uploaded and verified ($nchunks chunk(s), $size) in $(( $(date +%s) - T0 ))s"
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
  if [ ! -f "$STATE_DIR.restored" ]; then
    log "SAVE FAILED: refusing to save because the state was never restored"
    echo "::error title=Save refused::state was never restored (the restore step must run first)"
    return 1
  fi
  local rc=0
  set +e
  (
    set -e     # explicit: any failing step inside must abort this save immediately
    if lock_acquire; then trap 'rm -rf "$WORK/state.lock.d"' EXIT
    elif [ -n "${SAVE_ANYWAY:-}" ]; then log "lock busy: saving anyway"
    else log "another save still holds the lock after ${LOCK_WAIT:-90}s"; exit 1; fi
    _save_locked
  )
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    log "SAVE FAILED (rc=$rc): this snapshot was not stored; the previous complete snapshot is still intact and the next autosave will retry"
    echo "::error title=State save failed::upload did not complete (rc=$rc); the previous snapshot is intact, next autosave will retry"
  fi
  return "$rc"
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

install_nginx() {   # small front proxy: one URL, per-terminal routing and optional basic auth (see boot)
  local b; b=$(command -v nginx || true)
  [ -n "$b" ] && { NGINX_BIN="$b"; return 0; }
  [ -x /usr/sbin/nginx ] && { NGINX_BIN=/usr/sbin/nginx; return 0; }   # /usr/sbin may not be on PATH
  need nginx nginx
  NGINX_BIN=$(command -v nginx || echo /usr/sbin/nginx)
  [ -x "$NGINX_BIN" ]
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
  # opencode v2 ships on npm as `@opencode/cli`; the old `opencode-ai` package is the v1 line and
  # self-migrates to v2 on first run — installing the v2 package directly avoids that surprise.
  docker exec -u $CUSER -e OV="${OPENCODE_VERSION:-latest}" $CNAME $sh \
      'npm install -g --allow-scripts=@opencode/cli "@opencode/cli@$OV" || sudo env "PATH=$PATH" npm install -g --allow-scripts=@opencode/cli "@opencode/cli@$OV"; v=$(opencode --version) && echo "opencode version: $v"'
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

  # web terminal: nginx front (one URL, several terminals) -> one ttyd per slot -> tmux sessions
  install_ttyd
  install_nginx
  local client_ok=0
  if build_client; then client_ok=1; else
    log "WARNING: custom client build failed — falling back to the stock ttyd UI (single terminal)"
  fi
  local cred="${TTYD_USER:-dev}:${TTYD_PASS:-}" auth=() cu=()
  if [ -n "${TTYD_PASS:-}" ]; then auth=(-c "$cred"); cu=(-u "$cred"); fi

  # One ttyd per slot; slot 1 keeps the familiar "main" tmux session, extras are "main-2", "main-3"…
  local i port sess tmuxcmd
  for i in $(seq 1 "$TERM_SLOTS"); do
    port=$((TTYD_SLOT_BASE + i - 1))
    sess="main"; [ "$i" -gt 1 ] && sess="main-$i"
    tmuxcmd="tmux -u new -A -s $sess \\; set -g status off \\; set -g set-clipboard on \\; set -g history-limit 50000 \\; set -g escape-time 10 || exec bash -l"
    nohup ttyd -W -i lo -p "$port" "${auth[@]}" \
      docker exec -it -u $CUSER -w /workspaces -e TERM=xterm-256color $CNAME bash -lc "$tmuxcmd" \
      >"$WORK/ttyd-$i.log" 2>&1 &
  done

  # nginx serves the app itself and routes /tN/token + /tN/ws to slot N. When a password is set it
  # asks the browser for it once (page + /token) and injects the Authorization header on the
  # WebSocket upgrade only: Safari/WebKit never sends Basic credentials on ws:// (ttyd#1437), which
  # used to leave the terminal reconnecting forever. Nothing is exposed by that: the shell stays
  # locked by ttyd's AuthToken, which the password-protected /token endpoint alone hands out.
  mkdir -p "$WORK/nginx-tmp"
  local auth_srv="" ws_auth=""
  if [ -n "${TTYD_PASS:-}" ]; then
    printf '%s:%s\n' "${TTYD_USER:-dev}" "$(printf %s "$TTYD_PASS" | openssl passwd -apr1 -stdin)" > "$WORK/htpasswd"
    local cred_b64; cred_b64=$(printf %s "$cred" | base64 -w0)
    auth_srv=$(printf '    auth_basic "terminal";\n    auth_basic_user_file %s;\n' "$WORK/htpasswd")
    ws_auth=$(printf '      proxy_set_header Authorization "Basic %s";\n' "$cred_b64")
  fi

  if [ "$client_ok" = 1 ]; then
    printf '{"slots":%d}\n' "$TERM_SLOTS" > "$WORK/info.json"
    : > "$WORK/nginx-slots.conf"
    for i in $(seq 1 "$TERM_SLOTS"); do
      port=$((TTYD_SLOT_BASE + i - 1))
      cat >> "$WORK/nginx-slots.conf" <<NGX
    location = /t$i/token {
      proxy_pass http://127.0.0.1:$port/token;
      proxy_http_version 1.1;
      proxy_set_header Host \$host;
      proxy_read_timeout 30s;
    }
    location = /t$i/ws {
      auth_basic off;
      proxy_pass http://127.0.0.1:$port/ws;
      proxy_http_version 1.1;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host \$host;
$ws_auth
      proxy_read_timeout 86400s;
      proxy_send_timeout 86400s;
    }
NGX
    done
    cat > "$WORK/nginx.conf" <<NGX
daemon off;
pid $WORK/nginx.pid;
error_log $WORK/nginx-error.log warn;
events { worker_connections 256; }
http {
  access_log off;
  client_body_temp_path $WORK/nginx-tmp/body;
  proxy_temp_path $WORK/nginx-tmp/proxy;
  fastcgi_temp_path $WORK/nginx-tmp/fastcgi;
  uwsgi_temp_path $WORK/nginx-tmp/uwsgi;
  scgi_temp_path $WORK/nginx-tmp/scgi;
  server {
    listen 127.0.0.1:$TTYD_PORT;
$auth_srv
    location = / {
      root $WORK;
      try_files /client.html =404;
      default_type text/html;
      add_header Cache-Control "no-store";
    }
    location = /info {
      root $WORK;
      try_files /info.json =404;
      default_type application/json;
      add_header Cache-Control "no-store";
    }
    include $WORK/nginx-slots.conf;
  }
}
NGX
  else
    cat > "$WORK/nginx.conf" <<NGX
daemon off;
pid $WORK/nginx.pid;
error_log $WORK/nginx-error.log warn;
events { worker_connections 256; }
http {
  access_log off;
  client_body_temp_path $WORK/nginx-tmp/body;
  proxy_temp_path $WORK/nginx-tmp/proxy;
  fastcgi_temp_path $WORK/nginx-tmp/fastcgi;
  uwsgi_temp_path $WORK/nginx-tmp/uwsgi;
  scgi_temp_path $WORK/nginx-tmp/scgi;
  server {
    listen 127.0.0.1:$TTYD_PORT;
$auth_srv
    location = /ws {
      auth_basic off;                 # ttyd authenticates /ws itself with the AuthToken
      proxy_pass http://127.0.0.1:$TTYD_SLOT_BASE;
      proxy_http_version 1.1;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection "upgrade";
$ws_auth
      proxy_read_timeout 86400s;
      proxy_send_timeout 86400s;
    }
    location / {
      proxy_pass http://127.0.0.1:$TTYD_SLOT_BASE;
      proxy_http_version 1.1;
      proxy_set_header Host \$host;
    }
  }
}
NGX
  fi
  nohup "$NGINX_BIN" -c "$WORK/nginx.conf" >"$WORK/nginx.log" 2>&1 &

  local code=000 page=000 slots_ok=0 hc app_ok=0 up=0
  for _ in $(seq 20); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$TTYD_PORT/" || true)
    case "$code" in 200|401) break;; esac; sleep 1
  done
  page=$(curl -s "${cu[@]}" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$TTYD_PORT/" || true)
  if [ "$client_ok" = 1 ]; then
    # download first: `curl | grep -q` trips pipefail as soon as grep exits early (SIGPIPE)
    curl -s "${cu[@]}" -o "$WORK/page.html" "http://127.0.0.1:$TTYD_PORT/" || true
    if [ "$page" = 200 ] && grep -q 'id="tabs"' "$WORK/page.html"; then app_ok=1; fi
    for i in $(seq 1 "$TERM_SLOTS"); do
      hc=$(curl -s "${cu[@]}" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$TTYD_PORT/t$i/token" || true)
      case "$hc" in 000|502|503|504) log "WARNING: terminal slot $i is not answering (HTTP $hc)";; *) slots_ok=$((slots_ok + 1));; esac
    done
    [ "$app_ok" = 1 ] && [ "$slots_ok" = "$TERM_SLOTS" ] && up=1
  else
    [ "$page" = 200 ] && up=1
  fi
  if [ "$up" = 1 ]; then
    if [ "$client_ok" = 1 ]; then
      log "web terminal is up: $slots_ok/$TERM_SLOTS slots, HTTP $code (auth: $([ -n "${TTYD_PASS:-}" ] && echo "on" || echo OFF))"
    else
      log "web terminal is up (single-terminal fallback UI), HTTP $page (auth: $([ -n "${TTYD_PASS:-}" ] && echo "on" || echo OFF))"
    fi
  else
    log "ERROR: web terminal is not healthy (page=$page app=$app_ok slots=$slots_ok/$TERM_SLOTS)"
    cat "$WORK"/ttyd-*.log "$WORK/nginx-error.log" 2>/dev/null || true
    $SUDO ss -ltnp | grep -E ":$TTYD_PORT|:$TTYD_SLOT_BASE" || true
    exit 1
  fi
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
  log "final: stopping container, then saving the final snapshot"
  timeout 30 docker stop -t 15 $CNAME >/dev/null 2>&1 || docker kill $CNAME >/dev/null 2>&1 || true
  if LOCK_WAIT=20 SAVE_ANYWAY=1 FORCE_SAVE=1 save; then
    log "FINAL SAVE SUCCESSFUL: the next run will restore this snapshot"
    echo "::notice title=State saved::Final snapshot uploaded successfully — the next run will continue from it."
    { echo "### State saved successfully"; echo "Final snapshot uploaded and verified; the next run restores from it. No action needed."; } \
      >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
  else
    log "FINAL SAVE FAILED: see the error above; the previous complete snapshot is still intact"
    exit 1
  fi
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
      wait "$spid" || log "autosave reported a problem (details above) — the next autosave will retry"
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
