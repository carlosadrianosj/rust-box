#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════
#  RustBox POC1-V2 — Stop All Dev Services
# ═══════════════════════════════════════════════════════════════════

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
info() { echo -e "${CYAN}[→]${NC} $1"; }

echo ""
echo -e "${RED}Stopping RustBox dev services...${NC}"
echo ""

# Kill server
info "Killing RustBox Server (:8443, :4433)..."
lsof -ti :8443 2>/dev/null | xargs kill 2>/dev/null || true
lsof -ti :4433 2>/dev/null | xargs kill 2>/dev/null || true
log "Server stopped"

# Kill web UI
info "Killing Web UI server (:8080)..."
lsof -ti :8080 2>/dev/null | xargs kill 2>/dev/null || true
log "Web UI stopped"

# Stop PostgreSQL
info "Stopping PostgreSQL (Docker)..."
docker compose down 2>&1 | tail -3
log "PostgreSQL stopped"

echo ""
log "All services stopped."
echo ""
