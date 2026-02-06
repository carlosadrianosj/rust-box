#!/usr/bin/env bash
set -euo pipefail

# ===================================================================
#  RustBox POC1-V2 -- CLI Test Script
#
#  Usage:
#    ./test-cli.sh              Single-user: login + upload + files + status
#    ./test-cli.sh sync         Multi-user: clean DB, 2 users, upload, verify isolation
#    ./test-cli.sh files        Quick: list files for both users
# ===================================================================

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[ok]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[>]${NC} $1"; }
sep()  { echo -e "${CYAN}-----------------------------------------------------------${NC}"; }

# -- Config --------------------------------------------------------
SERVER="${RUSTBOX_SERVER:-127.0.0.1:4433}"
USER1="user01"
PASS1="password"
USER2="user02"
PASS2="password"
DIR_USER1="/tmp/rustbox-test-user01"
DIR_USER2="/tmp/rustbox-test-user02"

# Run CLI from a specific vault dir but point cargo at workspace root
run_cli() {
    local workdir="$1"
    shift
    (cd "$workdir" && cargo run --manifest-path "$ROOT/Cargo.toml" -p rustbox-cli -- "$@")
}

# -- Verify server is running --------------------------------------
if ! lsof -ti :4433 >/dev/null 2>&1; then
    err "Server not running on :4433. Run ./start-dev.sh first."
fi

# ==================================================================
#  Subcommand dispatch
# ==================================================================
CMD="${1:-default}"

# ==================================================================
#  SUBCOMMAND: files -- login both users and show their files
# ==================================================================
if [ "$CMD" = "files" ]; then
    echo ""
    echo -e "${CYAN}===========================================================${NC}"
    echo -e "${CYAN}  RustBox -- List Files (both users)${NC}"
    echo -e "${CYAN}===========================================================${NC}"
    echo ""

    # -- user01 --
    sep
    echo -e "  ${YELLOW}$USER1${NC} files:"
    sep
    if [ -d "$DIR_USER1/.rustbox" ]; then
        RUSTBOX_PASSWORD="$PASS1" run_cli "$DIR_USER1" files 2>&1 || warn "user01 files failed"
    else
        warn "$USER1 vault not found at $DIR_USER1 -- run './test-cli.sh sync' first"
    fi

    echo ""

    # -- user02 --
    sep
    echo -e "  ${YELLOW}$USER2${NC} files:"
    sep
    if [ -d "$DIR_USER2/.rustbox" ]; then
        RUSTBOX_PASSWORD="$PASS2" run_cli "$DIR_USER2" files 2>&1 || warn "user02 files failed"
    else
        warn "$USER2 vault not found at $DIR_USER2 -- run './test-cli.sh sync' first"
    fi

    echo ""
    exit 0
fi

# ==================================================================
#  SUBCOMMAND: sync -- cross-user isolation test
# ==================================================================
if [ "$CMD" = "sync" ]; then
    # Test files -- user01 gets the PNG, user02 gets the PDF
    FILE_USER1="$ROOT/rust_box_v4.png"
    FILE_USER2="/Users/carlosadrianosj/Documents/rust-g2i/files-test/CV_Carlos_Adriano_Systems_Engineer.pdf"

    echo ""
    echo -e "${CYAN}===========================================================${NC}"
    echo -e "${CYAN}  RustBox -- Cross-User Sync Test${NC}"
    echo -e "${CYAN}  $USER1 + $USER2 @ $SERVER${NC}"
    echo -e "${CYAN}===========================================================${NC}"
    echo ""

    # -- Verify test files exist -----------------------------------
    [ -f "$FILE_USER1" ] || err "Test file not found: $FILE_USER1"
    [ -f "$FILE_USER2" ] || err "Test file not found: $FILE_USER2"
    log "Test files OK: $(basename "$FILE_USER1"), $(basename "$FILE_USER2")"

    # -- Step 1: Clean slate ---------------------------------------
    echo ""
    info "Step 1: Cleaning database + local vaults..."
    docker compose -f "$ROOT/docker-compose.yml" exec -T postgres psql -U rustbox -c \
        "DELETE FROM manifests; DELETE FROM blobs; DELETE FROM users;" \
        > /dev/null 2>&1 || warn "DB clean failed (maybe empty already)"
    rm -rf "$DIR_USER1" "$DIR_USER2"
    mkdir -p "$DIR_USER1" "$DIR_USER2"
    log "Clean slate"

    # -- Step 2: Login user01 + upload -----------------------------
    echo ""
    sep
    info "Step 2: Login $USER1 + upload $(basename "$FILE_USER1")"
    sep

    RUSTBOX_USERNAME="$USER1" RUSTBOX_PASSWORD="$PASS1" \
        run_cli "$DIR_USER1" login --server "$SERVER" 2>&1
    log "$USER1 logged in"

    RUSTBOX_PASSWORD="$PASS1" \
        run_cli "$DIR_USER1" upload "$FILE_USER1" 2>&1
    log "$USER1 uploaded $(basename "$FILE_USER1")"

    # -- Step 3: Login user02 + upload -----------------------------
    echo ""
    sep
    info "Step 3: Login $USER2 + upload $(basename "$FILE_USER2")"
    sep

    RUSTBOX_USERNAME="$USER2" RUSTBOX_PASSWORD="$PASS2" \
        run_cli "$DIR_USER2" login --server "$SERVER" 2>&1
    log "$USER2 logged in"

    RUSTBOX_PASSWORD="$PASS2" \
        run_cli "$DIR_USER2" upload "$FILE_USER2" 2>&1
    log "$USER2 uploaded $(basename "$FILE_USER2")"

    # -- Step 4: Verify isolation -- user01 files ------------------
    echo ""
    sep
    info "Step 4: Verify isolation -- $USER1 should see ONLY $(basename "$FILE_USER1")"
    sep

    RUSTBOX_PASSWORD="$PASS1" run_cli "$DIR_USER1" files 2>&1

    # -- Step 5: Verify isolation -- user02 files ------------------
    echo ""
    sep
    info "Step 5: Verify isolation -- $USER2 should see ONLY $(basename "$FILE_USER2")"
    sep

    RUSTBOX_PASSWORD="$PASS2" run_cli "$DIR_USER2" files 2>&1

    # -- Summary ---------------------------------------------------
    echo ""
    echo -e "${GREEN}===========================================================${NC}"
    echo -e "${GREEN}  CLI Cross-User Test Complete!${NC}"
    echo -e "${GREEN}===========================================================${NC}"
    echo ""
    echo -e "  ${YELLOW}Now test WASM sync:${NC}"
    echo ""
    echo -e "  1. Open ${CYAN}http://localhost:8080/serve.html${NC}  (Cmd+Shift+R)"
    echo -e "  2. Login as ${CYAN}$USER1 / $PASS1${NC}"
    echo -e "  3. Click Sync -> should show ${GREEN}1 downloaded${NC} ($(basename "$FILE_USER1"))"
    echo -e "  4. Logout -> Login as ${CYAN}$USER2 / $PASS2${NC}"
    echo -e "  5. Click Sync -> should show ${GREEN}1 downloaded${NC} ($(basename "$FILE_USER2"))"
    echo -e "  6. Each user sees ONLY their own file"
    echo ""
    echo -e "  ${YELLOW}Quick check anytime:${NC}"
    echo -e "  ${CYAN}./test-cli.sh files${NC}  -- lists both users' files"
    echo ""
    exit 0
fi

# ==================================================================
#  DEFAULT: single-user test (login + upload + files + status)
# ==================================================================
USERNAME="${RUSTBOX_USERNAME:-user01}"
PASSWORD="${RUSTBOX_PASSWORD:-password}"
TEST_FILE="${2:-$ROOT/rust_box_v4.png}"

cd "$ROOT"

echo ""
echo -e "${CYAN}===========================================================${NC}"
echo -e "${CYAN}  RustBox CLI Test -- $USERNAME @ $SERVER${NC}"
echo -e "${CYAN}===========================================================${NC}"
echo ""

log "Server is running"

# -- Verify test file exists ---------------------------------------
if [ ! -f "$TEST_FILE" ]; then
    err "Test file not found: $TEST_FILE"
fi
FILE_SIZE=$(stat -f%z "$TEST_FILE" 2>/dev/null || stat --printf="%s" "$TEST_FILE" 2>/dev/null || echo "?")
log "Test file: $(basename "$TEST_FILE") ($FILE_SIZE bytes)"

# -- Clean previous vault -----------------------------------------
if [ -d ".rustbox" ]; then
    info "Removing previous .rustbox/ vault..."
    rm -rf .rustbox
    log "Clean slate"
fi

# -- Step 1: Login (auto-creates vault + registers + stores server)
echo ""
info "Step 1: Login (auto-init vault + register)..."
RUSTBOX_USERNAME="$USERNAME" RUSTBOX_PASSWORD="$PASSWORD" \
    cargo run -p rustbox-cli -- login --server "$SERVER" 2>&1
log "Login complete (server stored for future commands)"

# -- Step 2: Upload (no --server needed, reads stored address) ----
echo ""
info "Step 2: Uploading $(basename "$TEST_FILE") (no --server needed)..."
RUSTBOX_PASSWORD="$PASSWORD" \
    cargo run -p rustbox-cli -- upload "$TEST_FILE" 2>&1
log "Upload complete"

# -- Step 3: List server files (no --server needed) ---------------
echo ""
info "Step 3: Listing ALL server files (cross-client view, no --server)..."
RUSTBOX_PASSWORD="$PASSWORD" \
    cargo run -p rustbox-cli -- files 2>&1
log "Server file listing complete"

# -- Step 4: Status (shows user, server, tracked files) -----------
echo ""
info "Step 4: Status (local vault + stored server info)..."
cargo run -p rustbox-cli -- status 2>&1

# -- Summary -------------------------------------------------------
echo ""
echo -e "${GREEN}===========================================================${NC}"
echo -e "${GREEN}  CLI Test Complete!${NC}"
echo -e "${GREEN}===========================================================${NC}"
echo ""
echo -e "  ${YELLOW}Step 3 (files)${NC}   shows ALL server files (cross-client: Web + CLI + Tauri)"
echo -e "  ${YELLOW}Step 4 (status)${NC}  shows LOCAL vault state + stored server address"
echo ""
echo -e "  Now check Web UI: ${CYAN}http://localhost:8080/serve.html${NC}"
echo -e "  The uploaded file should appear after auto-sync (~4s)"
echo ""
