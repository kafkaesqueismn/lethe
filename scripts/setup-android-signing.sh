#!/usr/bin/env bash
# One-time setup: create lethe's Android signing key and give it to GitHub Actions.
#
# Android only installs signed apps, and updates must be signed with the SAME key,
# so this key is created once and kept. It lives in ~/.config/lethe-signing/
# (never in the repo). BACK THAT FOLDER UP: if the key is lost, existing installs
# can't be updated; people would have to uninstall and reinstall.
set -euo pipefail
REPO=${REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}
D=$HOME/.config/lethe-signing
mkdir -p "$D" && chmod 700 "$D"

if [[ -f $D/lethe-release.jks ]]; then
  echo "==> using existing key in $D"
else
  echo "==> creating a new signing key in $D"
  PW=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)
  keytool -genkeypair -keystore "$D/lethe-release.jks" -storetype PKCS12 -alias lethe \
    -keyalg RSA -keysize 4096 -validity 10000 -storepass "$PW" -keypass "$PW" -dname "CN=lethe" >/dev/null
  printf '%s\n' "$PW" >"$D/password.txt"
  chmod 600 "$D"/*
fi

echo "==> storing it as encrypted GitHub Actions secrets on $REPO"
base64 -w0 "$D/lethe-release.jks" | gh secret set ANDROID_KEYSTORE_B64 --repo "$REPO"
tr -d '\n' <"$D/password.txt" | gh secret set ANDROID_KEYSTORE_PASSWORD --repo "$REPO"
echo "Done. Back up $D somewhere safe (e.g. an encrypted USB stick or password manager)."
