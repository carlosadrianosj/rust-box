#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════
#  RustBox POC1-V2 — Dev Environment Launcher
#  Builds all crates, starts PostgreSQL + Server + Web UI
# ═══════════════════════════════════════════════════════════════════

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[→]${NC} $1"; }

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  RustBox POC1-V2 — Dev Environment${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# ── Step 1: Kill existing processes ────────────────────────────────
info "Killing existing processes on :8443, :4433, :8080..."
lsof -ti :8443 2>/dev/null | xargs kill 2>/dev/null || true
lsof -ti :4433 2>/dev/null | xargs kill 2>/dev/null || true
lsof -ti :8080 2>/dev/null | xargs kill 2>/dev/null || true
sleep 1
log "Ports freed"

# ── Step 2: Start PostgreSQL ──────────────────────────────────────
info "Starting PostgreSQL (Docker)..."
docker compose up -d postgres 2>&1 | grep -v "^$" | tail -3

info "Waiting for PostgreSQL to be healthy..."
for i in $(seq 1 30); do
    STATUS=$(docker compose ps --format "{{.Status}}" 2>/dev/null | head -1)
    if echo "$STATUS" | grep -q "healthy"; then
        log "PostgreSQL is healthy"
        break
    fi
    if [ "$i" -eq 30 ]; then
        err "PostgreSQL failed to start after 30s"
        echo "  Run: docker compose logs postgres"
        exit 1
    fi
    sleep 1
done

# ── Step 3: Build all crates ──────────────────────────────────────
info "Building rustbox-server..."
cargo build -p rustbox-server 2>&1 | grep -v "^$" | grep -v "Compiling" | tail -3
log "Server built"

info "Building rustbox-cli..."
cargo build -p rustbox-cli 2>&1 | grep -v "^$" | grep -v "Compiling" | tail -3
cp "$ROOT/target/debug/rustbox" "$ROOT/rustbox"
log "CLI built (binary copied to project root: ./rustbox)"

info "Building rustbox-wasm (wasm-pack)..."
cd "$ROOT/rustbox-wasm"
wasm-pack build --target web 2>&1 | grep -v "^$" | tail -3
cd "$ROOT"
log "WASM built"

# ── Step 4: Start RustBox Server (background) ─────────────────────
info "Starting RustBox Server (HTTP :8443 + QUIC :4433)..."
DATABASE_URL=postgres://rustbox:rustbox_secret@127.0.0.1:5432/rustbox \
RUST_LOG=info \
cargo run -p rustbox-server > /tmp/rustbox-server.log 2>&1 &
SERVER_PID=$!

# Wait for server to be ready
for i in $(seq 1 15); do
    if lsof -ti :8443 >/dev/null 2>&1 && lsof -ti :4433 >/dev/null 2>&1; then
        log "Server running (PID $SERVER_PID)"
        break
    fi
    if [ "$i" -eq 15 ]; then
        err "Server failed to start. Check /tmp/rustbox-server.log"
        exit 1
    fi
    sleep 1
done

# ── Step 5: Start Web UI server (background) ──────────────────────
info "Starting Web UI server (:8080)..."
cd "$ROOT/rustbox-wasm"
python3 -m http.server 8080 > /tmp/rustbox-webui.log 2>&1 &
WEBUI_PID=$!
cd "$ROOT"

sleep 1
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/serve.html | grep -q 200; then
    log "Web UI running (PID $WEBUI_PID)"
else
    err "Web UI failed to start. Check /tmp/rustbox-webui.log"
fi

# ── Summary ───────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  All services running!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}PostgreSQL${NC}     :5432  (Docker)"
echo -e "  ${CYAN}RustBox Server${NC} :8443 HTTP + :4433 QUIC  (PID $SERVER_PID)"
echo -e "  ${CYAN}Web UI${NC}         :8080  (PID $WEBUI_PID)"
echo ""
echo -e "  Logs:"
echo -e "    Server → /tmp/rustbox-server.log"
echo -e "    Web UI → /tmp/rustbox-webui.log"
echo ""
echo -e "${YELLOW}── Test Web (WASM) ──────────────────────────────────────────${NC}"
echo -e "  Open: ${CYAN}http://localhost:8080/serve.html${NC}"
echo -e "  Login: user01 / password"
echo ""
echo -e "${YELLOW}── Test CLI ─────────────────────────────────────────────────${NC}"
echo -e "  ${CYAN}RUSTBOX_USERNAME=user01 RUSTBOX_PASSWORD=password \\${NC}"
echo -e "  ${CYAN}  ./rustbox login --server 127.0.0.1:4433${NC}"
echo ""
echo -e "  ${CYAN}RUSTBOX_PASSWORD=password ./rustbox upload /path/to/file${NC}"
echo -e "  ${CYAN}RUSTBOX_PASSWORD=password ./rustbox files${NC}"
echo -e "  ${CYAN}./rustbox status${NC}"
echo ""
echo -e "${YELLOW}── Integration Tests ────────────────────────────────────────${NC}"
echo -e "  ${CYAN}./test/test-cli.sh${NC}        (single-user)"
echo -e "  ${CYAN}./test/test-cli.sh sync${NC}   (multi-user isolation)"
echo ""
echo -e "${YELLOW}── Stop Everything ──────────────────────────────────────────${NC}"
echo -e "  ${CYAN}./test/stop-dev.sh${NC}  or  ${CYAN}kill $SERVER_PID $WEBUI_PID && docker compose down${NC}"
echo ""
