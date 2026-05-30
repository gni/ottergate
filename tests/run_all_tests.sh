#!/usr/bin/env bash

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

CONTAINER="ottergate-dind-host"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo -e "${BLUE}${BOLD}================================================================${RESET}"
echo -e "${BLUE}${BOLD}             Ottergate Complete Test Battery Runner             ${RESET}"
echo -e "${BLUE}${BOLD}================================================================${RESET}"

PASS_COUNT=0
FAIL_COUNT=0

report_phase() {
    local phase_name=$1
    local status=$2
    if [ "$status" = "PASS" ]; then
        echo -e "  [${GREEN}PASS${RESET}] $phase_name"
        ((PASS_COUNT++))
    else
        echo -e "  [${RED}FAIL${RESET}] $phase_name"
        ((FAIL_COUNT++))
    fi
}

# --- STEP 1: Static Syntax Analysis ---
echo -e "\n${BOLD}--- PHASE 1: Running Static Syntax Verification ---${RESET}"
if python3 "${PROJECT_DIR}/tests/verify_syntax.py"; then
    report_phase "Static Syntax Analysis" "PASS"
else
    report_phase "Static Syntax Analysis" "FAIL"
fi

# --- STEP 2: Go Unit Tests ---
echo -e "\n${BOLD}--- PHASE 2: Running Go Unit Tests (via Docker Go container) ---${RESET}"
# Runs tests in a temporary official Golang container on the host to avoid local environment dependencies
if docker run --rm -v "${PROJECT_DIR}:/app" -w /app golang:1.22-alpine go test ./...; then
    report_phase "Go Unit Tests Suite" "PASS"
else
    report_phase "Go Unit Tests Suite" "FAIL"
fi

# --- STEP 3: Integration Tests (inside DinD wrapper) ---
echo -e "\n${BOLD}--- PHASE 3: Running DinD Zero-Trust Integration Proxy Tests ---${RESET}"
# Check if outer wrapper is running
RUNNING=$(docker inspect -f '{{.State.Running}}' "${CONTAINER}" 2>/dev/null)
if [ "$RUNNING" != "true" ]; then
    echo -e "${RED}[FAIL] Wrapper container '${CONTAINER}' is not active. Run 'docker compose up -d' first.${RESET}"
    report_phase "Integration Proxy Tests" "FAIL"
else
    if docker exec "${CONTAINER}" /app/tests/run_complete_suite.sh; then
        report_phase "Integration Proxy Tests" "PASS"
    else
        report_phase "Integration Proxy Tests" "FAIL"
    fi
fi

# --- STEP 4: gVisor Sandboxing Verification ---
echo -e "\n${BOLD}--- PHASE 4: Running gVisor Sandboxing Audit ---${RESET}"
if [ "$RUNNING" != "true" ]; then
    echo -e "${RED}[FAIL] Wrapper container '${CONTAINER}' is not active.${RESET}"
    report_phase "gVisor Sandboxing Audit" "FAIL"
else
    GVISOR_PASS=true
    echo -e "${BLUE}Running Bash gVisor Audit...${RESET}"
    if ! docker exec "${CONTAINER}" /app/tests/test_gvisor_features.sh; then
        GVISOR_PASS=false
    fi
    echo -e "\n${BLUE}Running Python gVisor Audit...${RESET}"
    if ! docker exec "${CONTAINER}" /app/tests/test_gvisor_features.py; then
        GVISOR_PASS=false
    fi
    echo -e "\n${BLUE}Running Node.js gVisor Audit...${RESET}"
    if ! docker exec "${CONTAINER}" /app/tests/test_gvisor_features.js; then
        GVISOR_PASS=false
    fi

    if [ "$GVISOR_PASS" = "true" ]; then
        report_phase "gVisor Sandboxing Audit" "PASS"
    else
        report_phase "gVisor Sandboxing Audit" "FAIL"
    fi
fi

echo -e "\n${BLUE}${BOLD}================================================================${RESET}"
echo -e "${BOLD}                 Unified Test Suite Summary                     ${RESET}"
echo -e "${BLUE}${BOLD}================================================================${RESET}"
echo -e "  Total Test Phases Passed: ${GREEN}${PASS_COUNT}${RESET}"
echo -e "  Total Test Phases Failed: ${RED}${FAIL_COUNT}${RESET}"
echo -e "${BLUE}${BOLD}================================================================${RESET}"

if [ $FAIL_COUNT -eq 0 ]; then
    exit 0
else
    exit 1
fi
