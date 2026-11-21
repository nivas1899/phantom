#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
echo "Starting PHANTOM Web UI on http://localhost:9090"
sleep 1 && xdg-open http://localhost:9090 2>/dev/null &
python cli.py web --port 9090
