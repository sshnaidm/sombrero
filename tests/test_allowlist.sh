#!/bin/bash
# Test allowlist functionality

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DATA="$SCRIPT_DIR/test_data"
IMPLEMENTATION="$1"  # "python" or "go"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "========================================="
echo "Testing: Allowlist Functionality ($IMPLEMENTATION)"
echo "========================================="

# Set command based on implementation
if [ "$IMPLEMENTATION" = "python" ]; then
    CMD="python3 secscript.py"
    ALLOWLIST_FLAG="--allowlist"
elif [ "$IMPLEMENTATION" = "go" ]; then
    CMD="./secscript-go"
    ALLOWLIST_FLAG="--allowlist"
else
    echo "Error: Must specify 'python' or 'go' as first argument"
    exit 2
fi

# Test 1: Without allowlist (baseline)
echo ""
echo "Test 1: Scanning without allowlist (baseline)..."
set +e  # Temporarily disable exit on error
# Run from test_data directory to avoid loading default allowlist
if [ "$IMPLEMENTATION" = "python" ]; then
    OUTPUT_NO_ALLOWLIST=$(cd "$TEST_DATA" && python3 ../../secscript.py all_patterns.txt --dry-run 2>&1)
else
    OUTPUT_NO_ALLOWLIST=$(cd "$TEST_DATA" && ../../secscript-go --dry-run all_patterns.txt 2>&1)
fi
set -euo pipefail  # Re-enable
echo -e "${GREEN}✓ PASS${NC}: Baseline scan completed"

# Test 2: With allowlist
echo ""
echo "Test 2: Scanning with allowlist..."
set +e  # Temporarily disable exit on error
if [ "$IMPLEMENTATION" = "python" ]; then
    OUTPUT_WITH_ALLOWLIST=$($CMD "$TEST_DATA/all_patterns.txt" --dry-run $ALLOWLIST_FLAG "$TEST_DATA/allowlist_test" 2>&1)
else
    OUTPUT_WITH_ALLOWLIST=$($CMD --dry-run $ALLOWLIST_FLAG "$TEST_DATA/allowlist_test" "$TEST_DATA/all_patterns.txt" 2>&1)
fi
set -euo pipefail  # Re-enable

# Verify allowlist was loaded
if echo "$OUTPUT_WITH_ALLOWLIST" | grep -q "Loaded allowlist"; then
    echo -e "${GREEN}✓ PASS${NC}: Allowlist loaded successfully"
else
    echo -e "${RED}✗ FAIL${NC}: Allowlist not loaded"
    exit 1
fi

# Test 3: Verify exact match exclusion
echo ""
echo "Test 3: Verifying exact match exclusion (test_password_123)..."
if ! echo "$OUTPUT_WITH_ALLOWLIST" | grep -q "test_password_123"; then
    echo -e "${GREEN}✓ PASS${NC}: Exact match excluded (test_password_123)"
else
    echo -e "${RED}✗ FAIL${NC}: Exact match NOT excluded"
    exit 1
fi

# Test 4: Verify regex exclusion (AWS keys starting with AKIA)
echo ""
echo "Test 4: Verifying regex exclusion (^AKIA.*)..."
if ! echo "$OUTPUT_WITH_ALLOWLIST" | grep -q "AKIA"; then
    echo -e "${GREEN}✓ PASS${NC}: Regex pattern excluded (AKIA*)"
else
    echo -e "${RED}✗ FAIL${NC}: Regex pattern NOT excluded"
    exit 1
fi

# Test 5: Verify regex exclusion (GitHub tokens starting with ghp_)
echo ""
echo "Test 5: Verifying regex exclusion (^ghp_.*)..."
if ! echo "$OUTPUT_WITH_ALLOWLIST" | grep -q "ghp_"; then
    echo -e "${GREEN}✓ PASS${NC}: Regex pattern excluded (ghp_*)"
else
    echo -e "${RED}✗ FAIL${NC}: Regex pattern NOT excluded"
    exit 1
fi

# Test 6: Verify some patterns are still detected
echo ""
echo "Test 6: Verifying non-excluded patterns still detected..."
if echo "$OUTPUT_WITH_ALLOWLIST" | grep -q "password\|secret"; then
    echo -e "${GREEN}✓ PASS${NC}: Non-excluded patterns still detected"
else
    echo -e "${RED}✗ FAIL${NC}: No patterns detected (allowlist too broad)"
    exit 1
fi

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}All allowlist tests passed!${NC}"
echo -e "${GREEN}=========================================${NC}"
