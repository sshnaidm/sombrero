#!/bin/bash
# Main test runner - runs all tests for specified implementation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMPLEMENTATION="$1"  # "python" or "go"

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ -z "$IMPLEMENTATION" ]; then
    echo "Usage: $0 <python|go>"
    exit 2
fi

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}SecScript Test Suite${NC}"
echo -e "${BLUE}Implementation: $IMPLEMENTATION${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

# Track test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

run_test() {
    local test_name=$1
    local test_script=$2

    echo -e "${BLUE}Running: $test_name${NC}"
    echo "----------------------------------------"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if bash "$SCRIPT_DIR/$test_script" "$IMPLEMENTATION"; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        echo ""
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo -e "${RED}Test failed: $test_name${NC}"
        echo ""
        return 1
    fi
}

# Run all test suites
echo ""
run_test "Pattern Detection Tests" "test_patterns.sh" || true
echo ""
run_test "Allowlist Tests" "test_allowlist.sh" || true
echo ""
run_test "Line Skip Tests" "test_line_skip.sh" || true
echo ""
run_test "Entropy Detection Tests" "test_entropy.sh" || true
echo ""
run_test "Replace Mode Tests" "test_replace.sh" || true

# Summary
echo ""
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}=========================================${NC}"
echo "Total tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"

if [ $FAILED_TESTS -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"
    echo -e "${RED}=========================================${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
    echo -e "${GREEN}=========================================${NC}"
    exit 0
fi
