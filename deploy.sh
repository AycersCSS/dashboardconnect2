#!/bin/bash
# MergeIT Wazuh Dashboard — Deployment Script
# Run this on the dashboard VM to set up the connector + custom dashboard
# Usage: ./deploy.sh [start|stop|restart|status]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/.dashboard.pid"

start() {
    if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        echo "Dashboard is already running (PID $(cat "$PID_FILE"))"
        exit 1
    fi

    cd "$SCRIPT_DIR"

    # Install deps if needed
    if ! python3 -c "import flask" 2>/dev/null; then
        echo "[...] Installing Python dependencies..."
        pip3 install -r requirements.txt
    fi

    # Init DB if needed
    if [ ! -f connector.db ]; then
        echo "[...] Initializing database..."
        python3 -c "from models import init_db; init_db()"
    fi

    # Start server in background
    nohup python3 main.py > "$SCRIPT_DIR/dashboard.log" 2>&1 &
    echo $! > "$PID_FILE"
    echo "Dashboard started on port 5000 (PID $(cat $PID_FILE))"
    echo "Logs: $SCRIPT_DIR/dashboard.log"
}

stop() {
    if [ -f "$PID_FILE" ]; then
        kill $(cat "$PID_FILE") 2>/dev/null && echo "Dashboard stopped" || echo "No process found"
        rm -f "$PID_FILE"
    else
        echo "Dashboard is not running"
    fi
}

status() {
    if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        echo "Dashboard is running (PID $(cat "$PID_FILE"))"
    else
        echo "Dashboard is stopped"
    fi
}

case "${1:-start}" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; sleep 1; start ;;
    status)  status ;;
    *)       echo "Usage: $0 {start|stop|restart|status}" ;;
esac
