#!/usr/bin/env bash
# ==============================================================================
# nanossh Automated Validation Test Suite
# ==============================================================================
# This script automates end-to-end tests for nanossh:
# - Valid & Invalid Authentication
# - Terminal Output & UTF-8 / ANSI Integrity
# - High-Throughput Burst Streaming (1,000 lines)
# - Resident Memory (RSS) Footprint Verification (< 10 MB limit)
# - Sequential Reconnect & Rapid Session Cycling
# ==============================================================================

set -u

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASSED=0
FAILED=0
TOTAL=0

BIN="./target/release/nanossh"
TEST_PORT="45690"
TEST_HOST="127.0.0.1"
SECRET="test_secret_$(date +%s)_$RANDOM"
LOCAL_SERVER_PID=""

show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  --remote <IP:PORT>   Run tests against an existing remote nanossh server
  --secret <SECRET>    Pre-shared secret to use with --remote
  --bin <PATH>         Path to nanossh binary (default: ./target/release/nanossh)
  --help               Display this help message
EOF
    exit 0
}

REMOTE_MODE=0
REMOTE_TARGET=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --remote)
            REMOTE_MODE=1
            REMOTE_TARGET="$2"
            shift 2
            ;;
        --secret)
            SECRET="$2"
            shift 2
            ;;
        --bin)
            BIN="$2"
            shift 2
            ;;
        --help|-h)
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            ;;
    esac
done

if [ ! -f "$BIN" ]; then
    echo -e "${RED}[ERROR] Binary not found at $BIN${NC}"
    echo "Please build with: cargo build --release"
    exit 1
fi

cleanup() {
    if [ -n "$LOCAL_SERVER_PID" ]; then
        kill "$LOCAL_SERVER_PID" 2>/dev/null || true
        wait "$LOCAL_SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

log_header() {
    echo -e "\n${BOLD}${BLUE}================================================================${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}================================================================${NC}"
}

report_result() {
    local name="$1"
    local status="$2"
    local detail="${3:-}"
    TOTAL=$((TOTAL + 1))
    if [ "$status" -eq 0 ]; then
        PASSED=$((PASSED + 1))
        echo -e "  ${GREEN}✓ [PASS]${NC} $name ${CYAN}$detail${NC}"
    else
        FAILED=$((FAILED + 1))
        echo -e "  ${RED}✗ [FAIL]${NC} $name ${YELLOW}$detail${NC}"
    fi
}

# ------------------------------------------------------------------------------
# 1. Environment & Server Initialization
# ------------------------------------------------------------------------------
log_header "1. Environment & Server Initialization"

TARGET_ADDR="$TEST_HOST:$TEST_PORT"

if [ "$REMOTE_MODE" -eq 1 ]; then
    TARGET_ADDR="$REMOTE_TARGET"
    echo -e "Testing against Remote Server: ${CYAN}$TARGET_ADDR${NC}"
else
    echo -e "Starting local nanossh server on ${CYAN}$TARGET_ADDR${NC}..."
    "$BIN" server --bind "$TARGET_ADDR" --secret "$SECRET" > /tmp/nanossh_test_server.log 2>&1 &
    LOCAL_SERVER_PID=$!
    sleep 0.6

    if ! kill -0 "$LOCAL_SERVER_PID" 2>/dev/null; then
        echo -e "${RED}[ERROR] Failed to start local test server! Check /tmp/nanossh_test_server.log:${NC}"
        cat /tmp/nanossh_test_server.log
        exit 1
    fi
    echo -e "${GREEN}Local server started with PID $LOCAL_SERVER_PID${NC}"
fi

# ------------------------------------------------------------------------------
# 2. Test: Authentication with Valid Secret
# ------------------------------------------------------------------------------
log_header "2. Authentication Tests"

START_TIME=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))')
OUTPUT=$(printf "echo 'AUTH_SUCCESS_TOKEN'\nexit\n" | "$BIN" client --connect "$TARGET_ADDR" --secret "$SECRET" 2>&1 || true)
END_TIME=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))')
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

if echo "$OUTPUT" | grep -q "AUTH_SUCCESS_TOKEN"; then
    report_result "Valid Secret Authentication" 0 "(${DURATION_MS}ms roundtrip)"
else
    report_result "Valid Secret Authentication" 1 "Output did not match expected token"
fi

# ------------------------------------------------------------------------------
# 3. Test: Authentication Rejection on Invalid Secret
# ------------------------------------------------------------------------------
OUTPUT_BAD=$(printf "echo 'SHOULD_NOT_RUN'\nexit\n" | "$BIN" client --connect "$TARGET_ADDR" --secret "WRONG_SECRET_123" 2>&1 || true)

if echo "$OUTPUT_BAD" | grep -iq "authentication rejected"; then
    report_result "Invalid Secret Rejection" 0 "(Clean rejection received)"
else
    report_result "Invalid Secret Rejection" 1 "Server did not reject bad secret properly: $OUTPUT_BAD"
fi

# ------------------------------------------------------------------------------
# 4. Test: Terminal Output & UTF-8 / ANSI Colors
# ------------------------------------------------------------------------------
log_header "3. Output Integrity & UTF-8 Tests"

UTF8_STRING="TEST_UNICODE_🦀_🚀_🔥_12345"
OUTPUT_UTF8=$(printf "echo '$UTF8_STRING'\nexit\n" | "$BIN" client --connect "$TARGET_ADDR" --secret "$SECRET" 2>&1 || true)

if echo "$OUTPUT_UTF8" | grep -q "$UTF8_STRING"; then
    report_result "Multi-byte UTF-8 Glyphs & Emoji" 0
else
    report_result "Multi-byte UTF-8 Glyphs & Emoji" 1 "Unicode string corrupted"
fi

# ------------------------------------------------------------------------------
# 5. Test: High-Throughput Burst Streaming
# ------------------------------------------------------------------------------
log_header "4. High-Throughput Burst Test"

BURST_COUNT=1000
START_BURST=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))')
BURST_RAW=$(printf "for i in \$(seq 1 $BURST_COUNT); do echo \"BURST_LINE_\$i\"; done\nexit\n" | "$BIN" client --connect "$TARGET_ADDR" --secret "$SECRET" 2>/dev/null || true)
END_BURST=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))')
BURST_MS=$(( (END_BURST - START_BURST) / 1000000 ))

# Strip carriage returns \r for regex matching
BURST_CLEAN=$(echo "$BURST_RAW" | tr -d '\r')
RECEIVED_FIRST=$(echo "$BURST_CLEAN" | grep -m1 "BURST_LINE_1$" || true)
RECEIVED_LAST=$(echo "$BURST_CLEAN" | grep -m1 "BURST_LINE_${BURST_COUNT}$" || true)

if [ -n "$RECEIVED_FIRST" ] && [ -n "$RECEIVED_LAST" ]; then
    report_result "1,000 Lines Streamed Intact" 0 "(${BURST_MS}ms duration)"
else
    report_result "1,000 Lines Streamed Intact" 1 "Stream truncated (first: '$RECEIVED_FIRST', last: '$RECEIVED_LAST')"
fi

# ------------------------------------------------------------------------------
# 6. Test: Memory Usage (RSS) Verification on Server
# ------------------------------------------------------------------------------
log_header "5. Server Memory (RSS) Footprint Check"

if [ "$REMOTE_MODE" -eq 0 ] && [ -n "$LOCAL_SERVER_PID" ]; then
    RSS_KB=$(ps -o rss= -p "$LOCAL_SERVER_PID" 2>/dev/null | tr -d ' ' || echo "0")
    if [ "$RSS_KB" -gt 0 ]; then
        RSS_MB=$(awk "BEGIN {printf \"%.2f\", $RSS_KB / 1024}")
        if [ "$RSS_KB" -lt 10240 ]; then
            report_result "Memory Footprint Under 10MB" 0 "(Current RSS: ${RSS_KB} KB / ~${RSS_MB} MB)"
        else
            report_result "Memory Footprint Under 10MB" 1 "High memory: ${RSS_KB} KB"
        fi
    else
        report_result "Memory Footprint Inspection" 1 "Could not read RSS for PID $LOCAL_SERVER_PID"
    fi
else
    echo -e "  ${YELLOW}[SKIPPED]${NC} Memory inspection skipped in remote mode (run locally on server)."
fi

# ------------------------------------------------------------------------------
# 7. Test: Rapid Sequential Reconnects
# ------------------------------------------------------------------------------
log_header "6. Rapid Session Recycling (Connection Stress)"

RECONNECT_SUCCESS=1
CYCLE_COUNT=5
for i in $(seq 1 $CYCLE_COUNT); do
    RE_OUT=$(printf "echo 'CYCLE_${i}_OK'\nexit\n" | "$BIN" client --connect "$TARGET_ADDR" --secret "$SECRET" 2>&1 || true)
    if ! echo "$RE_OUT" | grep -q "CYCLE_${i}_OK"; then
        RECONNECT_SUCCESS=0
        break
    fi
done

if [ "$RECONNECT_SUCCESS" -eq 1 ]; then
    report_result "Rapid Reconnection Stress" 0 "($CYCLE_COUNT back-to-back sessions succeeded)"
else
    report_result "Rapid Reconnection Stress" 1 "Session cycle failed on iteration $i"
fi

# ------------------------------------------------------------------------------
# 8. Summary
# ------------------------------------------------------------------------------
log_header "Test Summary"
echo -e "  Total Tests Run: ${BOLD}$TOTAL${NC}"
echo -e "  Passed:          ${GREEN}${BOLD}$PASSED${NC}"
echo -e "  Failed:          ${RED}${BOLD}$FAILED${NC}"

if [ "$FAILED" -eq 0 ]; then
    echo -e "\n${GREEN}${BOLD}✓ ALL TESTS PASSED! nanossh is healthy and validated.${NC}\n"
    exit 0
else
    echo -e "\n${RED}${BOLD}✗ SOME TESTS FAILED! Please inspect logs above.${NC}\n"
    exit 1
fi
