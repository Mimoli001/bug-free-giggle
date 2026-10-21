#!/usr/bin/env bash
# Locate a host Chrome for the remote browser, installing Google Chrome only when the runner image
# does not already contain a usable binary.  The remote browser runs outside the terminal container
# so its pages cannot read the terminal's files, cookies or loopback services.
set -euo pipefail

WORK="${1:-${RUNNER_TEMP:-/tmp}/state-work}"
mkdir -p "$WORK"
SUDO="${SUDO:-}"; [ "$(id -u)" -eq 0 ] && SUDO="" || [ -n "$SUDO" ] || SUDO="sudo"

find_chrome() {
  local candidate bin
  for candidate in google-chrome-stable google-chrome chromium chromium-browser; do
    bin="$(command -v "$candidate" 2>/dev/null || true)"
    if [ -n "$bin" ] && timeout 5 "$bin" --version >/dev/null 2>&1; then
      printf '%s\n' "$bin"
      return 0
    fi
  done
  for candidate in /usr/bin/google-chrome /usr/bin/google-chrome-stable /opt/google/chrome/chrome; do
    if [ -x "$candidate" ] && timeout 5 "$candidate" --version >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

chrome_bin="$(find_chrome || true)"
if [ -n "$chrome_bin" ]; then
  printf '%s\n' "$chrome_bin"
  exit 0
fi

log() { printf '[remote-chrome] %s\n' "$*" >&2; }
log "no Chrome found; installing Google Chrome from the official deb"
deb="$WORK/google-chrome-stable_current_amd64.deb"
if [ ! -s "$deb" ]; then
  curl -fsSL --retry 3 --connect-timeout 20 -o "$deb" \
    https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
fi
if ! DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y "$deb" >/dev/null 2>&1; then
  log "initial install failed; refreshing apt metadata and retrying"
  $SUDO apt-get update -qq || true
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y "$deb" >/dev/null
fi

chrome_bin="$(find_chrome || true)"
if [ -z "$chrome_bin" ]; then
  log "Chrome installation did not produce a binary"
  exit 1
fi
printf '%s\n' "$chrome_bin"
