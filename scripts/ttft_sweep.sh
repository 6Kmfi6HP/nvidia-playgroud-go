#!/usr/bin/env bash
# TTFT sweep: start serve with a config, wait for captcha pool, run N proxied requests.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVE="${SERVE:-/tmp/nvidia-serve}"
BENCH="${BENCH:-/tmp/nvidia-streambench}"
PORT="${PORT:-19080}"
RESULTS="${RESULTS:-/tmp/nvidia-ttft-results.tsv}"
RUNS="${RUNS:-2}"

cd "$ROOT"
go build -o "$SERVE" ./cmd/serve
go build -o "$BENCH" ./cmd/streambench

echo -e "config\trun\ttfb_ms\ttotal_ms\tstatus\tpool_ready_before" > "$RESULTS"

wait_pool() {
  local deadline=$((SECONDS + 180))
  while (( SECONDS < deadline )); do
    local body
    body="$(curl -sf "http://127.0.0.1:${PORT}/healthz" 2>/dev/null || true)"
    if [[ -n "$body" ]]; then
      local ready
      ready="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(d.get("pool",{}).get("ready",0))' "$body" 2>/dev/null || echo 0)"
      if [[ "$ready" -ge 1 ]]; then
        echo "$ready"
        return 0
      fi
    fi
    sleep 2
  done
  echo "0"
  return 1
}

run_config() {
  local name="$1"; shift
  local log="/tmp/nvidia-serve-${name}.log"
  echo "=== config=$name args=$* ===" >&2

  lsof -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | xargs kill 2>/dev/null || true
  sleep 1

  "$SERVE" -auto -addr ":$PORT" "$@" >"$log" 2>&1 &
  local pid=$!
  trap 'kill '"$pid"' 2>/dev/null || true' RETURN

  local ready
  if ! ready="$(wait_pool)"; then
    echo -e "${name}\t-\t-\t-\tPOOL_TIMEOUT\t0" >> "$RESULTS"
    echo "pool warm timeout; see $log" >&2
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    trap - RETURN
    return 0
  fi
  echo "pool ready=$ready" >&2

  for i in $(seq 1 "$RUNS"); do
    # ensure at least one token before each run when possible
    local before
    before="$(curl -sf "http://127.0.0.1:${PORT}/healthz" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("pool",{}).get("ready",0))' || echo 0)"
    local deadline=$((SECONDS + 120))
    while [[ "$before" -lt 1 ]] && (( SECONDS < deadline )); do
      sleep 2
      before="$(curl -sf "http://127.0.0.1:${PORT}/healthz" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("pool",{}).get("ready",0))' || echo 0)"
    done

    local out status ttfb total
    set +e
    out="$("$BENCH" -proxy "http://127.0.0.1:${PORT}" -max-tokens 48 -prompt "Reply with exactly: OK" 2>&1)"
    status=$?
    set -e
    ttfb_ms="$(echo "$out" | sed -n 's/.*ttfb_ms=\([0-9]*\).*/\1/p' | head -1)"
    total_ms="$(echo "$out" | sed -n 's/.*total=\([0-9.]*\)s.*/\1/p' | head -1)"
    # also accept total=123ms
    if [[ -z "${total_ms:-}" ]]; then
      total_ms="$(echo "$out" | grep -E 'total=' | head -1 | tr -d ' ' || true)"
    fi
    echo "run=$i before_ready=$before ttfb_ms=$ttfb_ms status=$status" >&2
    echo -e "${name}\t${i}\t${ttfb_ms:-ERR}\t${total_ms:-}\t${status}\t${before}" >> "$RESULTS"
    # brief pause so pool can refill
    sleep 3
  done

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  trap - RETURN
  sleep 2
}

# Focus: first-token latency with warmed pool; coalesce (eager-first) vs off; pool depth
run_config coalesce0_p2w1 -coalesce-ms=0 -pool-size=2 -pool-workers=1 -max-inflight=4
run_config coalesce16_p2w1 -coalesce-ms=16 -pool-size=2 -pool-workers=1 -max-inflight=4
run_config coalesce16_p3w2 -coalesce-ms=16 -pool-size=3 -pool-workers=2 -max-inflight=4
run_config coalesce16_p2w2 -coalesce-ms=16 -pool-size=2 -pool-workers=2 -max-inflight=4

echo "=== RESULTS ===" >&2
cat "$RESULTS"
