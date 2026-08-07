#!/usr/bin/env bash
# Brings up a dev-mode algod container, the spike README's own recipe
# (tests/fixtures/spike-reference/README.md), with two deliberate changes
# from that recipe (docs/design/011-test-harness-ci.md §8.1):
#
#   1. `sleep 12` -> a real `/v2/status` poll with a 120s deadline. A fixed
#      sleep on a shared hosted runner is how a workflow becomes
#      intermittently red for reasons that have nothing to do with the
#      code -- the one genuine flake class this module would otherwise be
#      introducing.
#   2. `$ALGOD_IMAGE` is a pinned DIGEST, never `:latest`. Every opcode
#      budget and protocol cap this project has ever measured (§9.1's
#      MAX_BOX_REFS_PER_TXN=8, the 2,048B pooled per-ref budget, etc.) was
#      measured against one specific go-algorand build -- a moving tag
#      would let a silent budget change read as a code regression.
#
# After bring-up, asserts POSITIVELY that /v2/teal/compile is actually live
# (§10 item 3): a future image on which the `algocfg` step silently no-ops
# would otherwise surface only as a confusing 404 deep inside the first
# deployment fixture that needs it.
set -euo pipefail

ALGOD_IMAGE="${ALGOD_IMAGE:-algorand/algod@sha256:9c667451da575abcf325c631bd24f845f051122e689628eba1c83daa3ebd3cbc}"
TOK="$(printf 'a%.0s' {1..64})"
CONTAINER_NAME="${ALGOD_CONTAINER_NAME:-ci_algod}"

# §10 item 2: fail loudly on a port collision rather than letting pytest
# talk to something unexpected.
for port in 4051 4052; do
  if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
    exec 3>&- 3<&- || true
    echo "FATAL: port ${port} is already bound on this runner" >&2
    exit 1
  fi
done

echo "Starting dev-mode algod (${ALGOD_IMAGE})..."
docker create --name "$CONTAINER_NAME" -p 4051:8080 -p 4052:7833 \
  -e DEV_MODE=1 -e START_KMD=1 \
  -e TOKEN="$TOK" -e ADMIN_TOKEN="$TOK" -e KMD_TOKEN="$TOK" \
  "$ALGOD_IMAGE"
docker start "$CONTAINER_NAME"

wait_for_status() {
  local deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    if curl -sS -f -H "X-Algo-API-Token: $TOK" http://localhost:4051/v2/status >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "FATAL: algod did not answer /v2/status within 120s" >&2
  docker logs "$CONTAINER_NAME" >&2 || true
  return 1
}

wait_for_status

# Enable the developer API (compile endpoint), then restart to apply.
docker exec "$CONTAINER_NAME" algocfg -d /algod/data set -p EnableDeveloperAPI -v true
docker restart "$CONTAINER_NAME"
wait_for_status

# §10 item 3: positively confirm the compile endpoint is really live, not
# merely that algod itself answered /v2/status.
compile_deadline=$((SECONDS + 30))
compile_ok=0
while (( SECONDS < compile_deadline )); do
  if curl -sS -f -H "X-Algo-API-Token: $TOK" -H "Content-Type: text/plain" \
       --data $'#pragma version 10\nint 1\nreturn' \
       http://localhost:4051/v2/teal/compile >/dev/null 2>&1; then
    compile_ok=1
    break
  fi
  sleep 2
done
if [[ "$compile_ok" -ne 1 ]]; then
  echo "FATAL: /v2/teal/compile did not come up (EnableDeveloperAPI may have silently no-op'd)" >&2
  exit 1
fi

echo "dev-mode algod is up, ports 4051/4052, developer API confirmed live."
