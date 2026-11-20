#!/usr/bin/env bash
# Verify an attack against a FRESH sandbox (new keys, new tokens, new bait), the way Mastyf verifies
# reports. The attack runs in its own container that can reach only the gateway and the Acme CRM app:
# no Docker socket, no volumes, no access to the authority or the key service.
#
#   sandbox/verify.sh path/to/attack.py [timeout_seconds=1800]
#
# Exit 0 = no flag; 10 = flag(s) captured; anything else = the run failed.
set -euo pipefail
ATTACK="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
LIMIT="${2:-1800}"
HERE="$(cd "$(dirname "$0")" && pwd)"
P="mastyf-verify-$$"
OUTDIR="$HERE/.verify-$$"; mkdir -p "$OUTDIR" && chmod 700 "$OUTDIR"
DC=(docker compose -p "$P" -f "$HERE/docker-compose.yml" -f "$HERE/verify.override.yml")
cleanup() {
  docker rm -f "$P-attack" >/dev/null 2>&1 || true
  OUT_BIND="$OUTDIR/out" "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$OUTDIR"
}
trap cleanup EXIT
cp "$ATTACK" "$OUTDIR/attack.py"   # Docker Desktop only shares some host folders
export OUT_BIND="$OUTDIR/out"

echo "== starting a fresh sandbox ($P)"
"${DC[@]}" up -d --build --quiet-pull 2>&1 | grep -iE "error|fail" || true
for _ in $(seq 1 300); do
  "${DC[@]}" exec -T app python -c \
    "import urllib.request;urllib.request.urlopen('http://localhost:8080/healthz',timeout=2)" >/dev/null 2>&1 && break
  sleep 2
done
[ -s "$OUTDIR/out/credentials.json" ] || { echo "sandbox did not start"; exit 2; }

echo "== running the attack (limit ${LIMIT}s); it can reach only gateway:8443 and app:8080"
docker run -d --name "$P-attack" --network "${P}_public" --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges --memory 1g --pids-limit 256 \
  -v "$OUTDIR/attack.py:/attack/attack.py:ro" -v "$OUTDIR/out/credentials.json:/attack/credentials.json:ro" \
  -e SANDBOX_CREDENTIALS=/attack/credentials.json -e SANDBOX_GATEWAY=https://gateway:8443 -e SANDBOX_APP=http://app:8080 \
  python:3.12-slim python /attack/attack.py >/dev/null
waited=0
while [ "$(docker inspect -f '{{.State.Running}}' "$P-attack")" = "true" ]; do
  [ "$waited" -ge "$LIMIT" ] && { echo "time limit reached; stopping the attack"; docker stop -t 5 "$P-attack" >/dev/null; break; }
  sleep 5; waited=$((waited + 5))
done
docker logs "$P-attack" > "$OUTDIR/attack.out" 2>&1
echo "attack finished after ~${waited}s (exit $(docker inspect -f '{{.State.ExitCode}}' "$P-attack"))"

echo "== attack output (last 40 lines, tokens hidden)"
grep -v '^MASTYF{' "$OUTDIR/attack.out" | tail -n 40 || true
echo "== checking flags"
"${DC[@]}" cp "$OUTDIR/attack.out" app:/tmp/attack.out >/dev/null
set +e
"${DC[@]}" exec -T app python /sandbox/check_flags.py /tmp/attack.out
rc=$?
set -e
exit $rc
