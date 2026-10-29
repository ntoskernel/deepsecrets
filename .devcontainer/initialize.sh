#!/bin/sh
# Runs on the host before every build and start of the dev container (devcontainer.json, initializeCommand).
#
# 1. Creates ~/.claude/ide and every DSBENCH_*_DIR that .env names, so Docker never creates a missing mount source
#    itself, as root.
# 2. Copies the host's whole trust store into certs/host-ca-bundle.pem: whatever the host trusts, the container will
#    too, a TLS-inspecting proxy's root included. Everything else in certs/ is yours and left alone.
set -eu
here=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$HOME/.claude/ide"
if [ -f "$here/.env" ]; then
    sed -n "s/^DSBENCH_[A-Z]*_DIR=//p" "$here/.env" | sed "s/^[\"']//; s/[\"']\$//" | while IFS= read -r dir; do
        if [ -n "$dir" ]; then mkdir -p "$dir"; fi
    done
fi

bundle="$here/certs/host-ca-bundle.pem"
mkdir -p "$here/certs"
if command -v security >/dev/null 2>&1; then
    # macOS: the system keychains, where an organisation's roots are installed
    security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain \
        /Library/Keychains/System.keychain > "$bundle"
elif command -v openssl >/dev/null 2>&1 && [ -f "$(openssl version -d | cut -d'"' -f2)/cert.pem" ]; then
    # the bundle the host's OpenSSL trusts by default; every major distribution points it at its full trust store
    cp -L "$(openssl version -d | cut -d'"' -f2)/cert.pem" "$bundle"
else
    rm -f "$bundle"
    echo "initialize.sh: no host trust store found; only certs/ goes into the container" >&2
fi
echo "initialize.sh: $(cat "$here"/certs/* 2>/dev/null | grep -c 'BEGIN CERTIFICATE' || true) certificate(s) in certs/"
