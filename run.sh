#!/usr/bin/env bash
# One-command local setup: starts a relay on this machine and opens lethe pointed at it.
#
#   ./run.sh            open the app
#   ./run.sh two        open two app windows (alice + bob) to try messaging yourself
#   ./run.sh cli NAME   terminal client with profile NAME
#   ./run.sh relay      just run the relay in the foreground
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$PWD
DEV=$ROOT/.dev
mkdir -p "$DEV"

echo "==> building (the first build takes a few minutes)"
cargo build -q -p lethe-relay -p lethe-cli

start_relay() {
  if [[ -f $DEV/relay.pid ]] && kill -0 "$(cat "$DEV/relay.pid")" 2>/dev/null; then
    echo "==> relay already running"
  else
    "$ROOT/target/debug/lethe-relay" --listen 127.0.0.1:5223 --host 127.0.0.1 --data-dir "$DEV/relay" >"$DEV/relay.log" 2>&1 &
    echo $! >"$DEV/relay.pid"
    for _ in $(seq 50); do grep -q 'lethe-relay://' "$DEV/relay.log" 2>/dev/null && break; sleep 0.1; done
    if ! grep -q 'lethe-relay://' "$DEV/relay.log"; then
      echo "relay failed to start:"; cat "$DEV/relay.log"; exit 1
    fi
    echo "==> relay started (log: .dev/relay.log)"
  fi
  RELAY=$(grep -o 'lethe-relay://[^ ]*' "$DEV/relay.log" | head -1)
  echo "    $RELAY"
}

stop_relay() {
  [[ -f $DEV/relay.pid ]] && kill "$(cat "$DEV/relay.pid")" 2>/dev/null || true
  rm -f "$DEV/relay.pid"
}

app() { # app [profile-name]
  local envs=(LETHE_DEFAULT_RELAY="$RELAY")
  [[ -n ${1:-} ]] && envs+=(LETHE_DATA_DIR="$DEV/$1")
  (cd "$ROOT/app/src-tauri" && env "${envs[@]}" cargo run -q)
}

case ${1:-app} in
  relay)
    stop_relay
    exec "$ROOT/target/debug/lethe-relay" --listen 127.0.0.1:5223 --host 127.0.0.1 --data-dir "$DEV/relay" ;;
  app)
    start_relay; trap stop_relay EXIT
    echo "==> opening the app"
    app ;;
  two)
    start_relay; trap stop_relay EXIT
    (cd app/src-tauri && cargo build -q)
    echo "==> opening two windows: alice and bob"
    app alice & app bob & wait ;;
  cli)
    start_relay; trap stop_relay EXIT
    name=${2:?usage: ./run.sh cli NAME}
    "$ROOT/target/debug/lethe" --profile "$DEV/cli-$name" --relay "$RELAY" --name "$name" ;;
  *) sed -n '2,8p' "$0"; exit 1 ;;
esac
