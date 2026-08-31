#!/usr/bin/env bash
# ensure_lsquic_patch.sh — guard the vendored lsquic build against silently
# losing the A+B HTTP/3 interop patch.
#
# The patch (docs/lsquic-4.7.0-http3-interop-a-b.patch) fixes two upstream
# defects that break the H3 handshake with strict clients (curl/ngtcp2):
#   A) no-SNI → CERT_CB_ERROR  (iquic_lookup_cert in lsquic_enc_sess_ietf.c)
#   B) ack-eliciting Initial not padded to 1200 bytes, RFC 9000 §14.1
#      (lsquic_mini_conn_ietf.c)
#
# third_party/ is gitignored, so a fresh `git submodule update` or checkout
# silently reverts the patch and the H3 path breaks again.  This hook
# re-applies it to the source, then FAILS LOUDLY if the prebuilt liblsquic.a
# is stale (built from unpatched source) — much cheaper than re-debugging the
# handshake.
#
# Wired into CMake as the `lsquic-patch-guard` custom target (see
# CMakeLists.txt); also runnable by hand:
#   bash scripts/ensure_lsquic_patch.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LSQUIC="$ROOT/third_party/lsquic"
PATCH="$ROOT/docs/lsquic-4.7.0-http3-interop-a-b.patch"
LIB="$LSQUIC/build/src/liblsquic/liblsquic.a"
PATCHED_SRC=(
  "$LSQUIC/src/liblsquic/lsquic_enc_sess_ietf.c"
  "$LSQUIC/src/liblsquic/lsquic_mini_conn_ietf.c"
)

[ -f "$PATCH" ] || { echo "FATAL: patch not found: $PATCH" >&2; exit 1; }
[ -d "$LSQUIC" ] || { echo "FATAL: vendored lsquic not found: $LSQUIC" >&2; exit 1; }

# The patch is already applied iff a reverse-apply is a no-op.
already_applied() {
  if git -C "$LSQUIC" rev-parse --git-dir >/dev/null 2>&1; then
    git -C "$LSQUIC" apply --check --reverse "$PATCH" >/dev/null 2>&1
  else
    patch --dry-run -R -p1 -d "$LSQUIC" < "$PATCH" >/dev/null 2>&1
  fi
}

if already_applied; then
    :
else
    echo "==> lsquic interop patch missing — applying $PATCH"
    if git -C "$LSQUIC" rev-parse --git-dir >/dev/null 2>&1; then
        git -C "$LSQUIC" apply "$PATCH"
    else
        patch -p1 -d "$LSQUIC" < "$PATCH"
    fi
fi

# ── Refuse to link a stale (unpatched) lib ─────────────────────────────
if [ ! -f "$LIB" ]; then
    echo "FATAL: $LIB not found — build it first, FROM THE PATCHED SOURCE:" >&2
    echo "  cmake -S $LSQUIC -B $LSQUIC/build && cmake --build $LSQUIC/build" >&2
    exit 1
fi

for f in "${PATCHED_SRC[@]}"; do
    if [ "$f" -nt "$LIB" ]; then
        echo "FATAL: $f is newer than $LIB — the lib was built from UNPATCHED source." >&2
        echo "       Source is now patched; rebuild it:" >&2
        echo "  cmake --build $LSQUIC/build" >&2
        exit 1
    fi
done

echo "==> lsquic interop patch applied; liblsquic.a is up to date"
