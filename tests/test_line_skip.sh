#!/bin/bash
# Test line skip functionality

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DATA="$SCRIPT_DIR/test_data"
IMPLEMENTATION="$1"  # "python" or "go"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "========================================="
echo "Testing: Line Skip Functionality ($IMPLEMENTATION)"
echo "========================================="

# Set command based on implementation
if [ "$IMPLEMENTATION" = "python" ]; then
    CMD="python3 secscript.py"
elif [ "$IMPLEMENTATION" = "go" ]; then
    CMD="./secscript-go"
else
    echo "Error: Must specify 'python' or 'go' as first argument"
    exit 2
fi

# Test 1: Without line skip (baseline)
echo ""
echo "Test 1: Scanning without line skip (baseline)..."
set +e  # Temporarily disable exit on error
# Run from test_data directory to avoid loading default allowlist
if [ "$IMPLEMENTATION" = "python" ]; then
    OUTPUT_NO_SKIP=$(cd "$TEST_DATA" && python3 ../../secscript.py line_skip_test.txt --dry-run 2>&1)
else
    OUTPUT_NO_SKIP=$(cd "$TEST_DATA" && ../../secscript-go --dry-run line_skip_test.txt 2>&1)
fi
set -euo pipefail  # Re-enable

BASELINE_COUNT=$(echo "$OUTPUT_NO_SKIP" | grep -c "password" || echo "0")
echo "Baseline found: $BASELINE_COUNT password instances"

if [ "$BASELINE_COUNT" -ge 4 ]; then
    echo -e "${GREEN}✓ PASS${NC}: Baseline scan found multiple passwords"
else
    echo -e "${RED}✗ FAIL${NC}: Baseline scan should find at least 4 passwords"
    exit 1
fi

# Test 2: With line skip
echo ""
echo "Test 2: Scanning with line skip..."
set +e  # Temporarily disable exit on error
if [ "$IMPLEMENTATION" = "python" ]; then
    OUTPUT_WITH_SKIP=$($CMD "$TEST_DATA/line_skip_test.txt" --dry-run --allowlist "$TEST_DATA/line_skip_allowlist" 2>&1)
else
    OUTPUT_WITH_SKIP=$($CMD --dry-run --allowlist "$TEST_DATA/line_skip_allowlist" "$TEST_DATA/line_skip_test.txt" 2>&1)
fi
set -euo pipefail  # Re-enable

# Verify line skip was loaded
if echo "$OUTPUT_WITH_SKIP" | grep -q "line skip patterns"; then
    echo -e "${GREEN}✓ PASS${NC}: Line skip patterns loaded"
else
    echo -e "${RED}✗ FAIL${NC}: Line skip patterns not loaded"
    exit 1
fi

# Test 3: Verify Event lines were skipped
echo ""
echo "Test 3: Verifying Event lines were skipped..."
if ! echo "$OUTPUT_WITH_SKIP" | grep -q "should_be_skipped_123"; then
    echo -e "${GREEN}✓ PASS${NC}: Event line skipped (should_be_skipped_123)"
else
    echo -e "${RED}✗ FAIL${NC}: Event line NOT skipped"
    exit 1
fi

# Test 4: Verify DEBUG lines were skipped
echo ""
echo "Test 4: Verifying DEBUG lines were skipped..."
if ! echo "$OUTPUT_WITH_SKIP" | grep -q "should_be_skipped_789"; then
    echo -e "${GREEN}✓ PASS${NC}: DEBUG line skipped (should_be_skipped_789)"
else
    echo -e "${RED}✗ FAIL${NC}: DEBUG line NOT skipped"
    exit 1
fi

# Test 5: Verify normal lines were NOT skipped
echo ""
echo "Test 5: Verifying normal lines were scanned..."
if echo "$OUTPUT_WITH_SKIP" | grep -q "should_be_found_456"; then
    echo -e "${GREEN}✓ PASS${NC}: Normal line scanned (should_be_found_456)"
else
    echo -e "${RED}✗ FAIL${NC}: Normal line was incorrectly skipped"
    exit 1
fi

# Test 6: Verify INFO lines were NOT skipped (only Event and DEBUG in allowlist)
echo ""
echo "Test 6: Verifying INFO lines were scanned..."
if echo "$OUTPUT_WITH_SKIP" | grep -q "should_be_found_012"; then
    echo -e "${GREEN}✓ PASS${NC}: INFO line scanned (should_be_found_012)"
else
    echo -e "${RED}✗ FAIL${NC}: INFO line was incorrectly skipped"
    exit 1
fi

# Test 7: Verify ConfigMap lines were NOT skipped
echo ""
echo "Test 7: Verifying ConfigMap lines were scanned..."
if echo "$OUTPUT_WITH_SKIP" | grep -q "should_be_found_345"; then
    echo -e "${GREEN}✓ PASS${NC}: ConfigMap line scanned (should_be_found_345)"
else
    echo -e "${RED}✗ FAIL${NC}: ConfigMap line was incorrectly skipped"
    exit 1
fi

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}All line skip tests passed!${NC}"
echo -e "${GREEN}=========================================${NC}"
