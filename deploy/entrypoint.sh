#!/bin/sh
# Start the assurance engine, wait for it to answer, then start the gateway.
#
# Starting the gateway first would have it report the engine as unreachable and mark the
# first analyses degraded, so the order matters. If either process dies the container
# exits, so a supervisor restarts the whole node rather than leaving half of it running.
set -eu

python -m uvicorn app:app --app-dir /app/ml-engine --host 127.0.0.1 --port 8000 --log-config=/dev/null &
ENGINE_PID=$!

echo "waiting for the assurance engine..."
i=0
while [ "$i" -lt 60 ]; do
  if node -e "fetch('http://127.0.0.1:8000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" 2>/dev/null; then
    echo "engine ready"
    break
  fi
  i=$((i + 1))
  sleep 1
done

node /app/dist/server.cjs &
GATEWAY_PID=$!

terminate() {
  kill -TERM "$ENGINE_PID" "$GATEWAY_PID" 2>/dev/null || true
  wait "$ENGINE_PID" "$GATEWAY_PID" 2>/dev/null || true
  exit 0
}
trap terminate TERM INT

wait -n "$ENGINE_PID" "$GATEWAY_PID"
echo "a component exited; shutting the node down"
terminate
