#!/bin/bash
cd "$(dirname "$0")"
for s in user-service order-service; do
  if [ -f logs/$s.pid ]; then kill "$(cat logs/$s.pid)" 2>/dev/null || true; rm -f logs/$s.pid; fi
done
echo "Backends stopped."
