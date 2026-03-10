#!/usr/bin/env bash
set -euo pipefail

# Local deploy script for ZeroClaw
# Usage: ./scripts/deploy-local.sh [--skip-test] [--no-restart]

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_DIR="$HOME/bin"
BINARY_NAME="zeroclaw"
DAEMON_PORT=42617

skip_test=false
no_restart=false

for arg in "$@"; do
    case "$arg" in
        --skip-test) skip_test=true ;;
        --no-restart) no_restart=true ;;
        --help|-h)
            echo "Usage: $0 [--skip-test] [--no-restart]"
            echo "  --skip-test   Skip cargo test/clippy before building"
            echo "  --no-restart  Don't restart the daemon after deploy"
            exit 0
            ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

cd "$REPO_DIR"

# 1. Validate
echo "==> [1/6] Checking formatting..."
cargo fmt --all -- --check

if [ "$skip_test" = false ]; then
    echo "==> [2/6] Running tests..."
    cargo test --lib -- process_registry process_tool shell:: --quiet
else
    echo "==> [2/6] Skipping tests (--skip-test)"
fi

# 2. Build
echo "==> [3/6] Building release binary..."
cargo build --release --quiet

# 3. Stop existing daemon
if [ "$no_restart" = false ]; then
    echo "==> [4/6] Stopping existing daemon..."
    EXISTING_PID=$(lsof -ti :"$DAEMON_PORT" 2>/dev/null || true)
    if [ -n "$EXISTING_PID" ]; then
        kill "$EXISTING_PID" 2>/dev/null || true
        sleep 1
        # Force kill if still alive
        if kill -0 "$EXISTING_PID" 2>/dev/null; then
            kill -9 "$EXISTING_PID" 2>/dev/null || true
            sleep 1
        fi
        echo "    Killed PID $EXISTING_PID"
    else
        echo "    No existing daemon found"
    fi
else
    echo "==> [4/6] Skipping daemon stop (--no-restart)"
fi

# 4. Install + sign
echo "==> [5/6] Installing binary..."
mkdir -p "$INSTALL_DIR"
cp "$REPO_DIR/target/release/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
codesign -s - --force "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null
echo "    Installed to $INSTALL_DIR/$BINARY_NAME ($(du -h "$INSTALL_DIR/$BINARY_NAME" | cut -f1) signed)"

# 5. Start daemon
if [ "$no_restart" = false ]; then
    echo "==> [6/6] Starting daemon..."
    LOG_FILE="/tmp/zeroclaw-daemon.log"
    nohup "$INSTALL_DIR/$BINARY_NAME" daemon > "$LOG_FILE" 2>&1 &
    NEW_PID=$!
    sleep 2

    if kill -0 "$NEW_PID" 2>/dev/null; then
        echo "    Daemon running (PID $NEW_PID, port $DAEMON_PORT)"
        echo "    Log: $LOG_FILE"
        echo ""
        "$INSTALL_DIR/$BINARY_NAME" doctor 2>&1 | grep "Summary"
    else
        echo "    ERROR: Daemon failed to start. Check $LOG_FILE"
        tail -10 "$LOG_FILE"
        exit 1
    fi
else
    echo "==> [6/6] Skipping daemon start (--no-restart)"
fi

echo ""
echo "Deploy complete."
