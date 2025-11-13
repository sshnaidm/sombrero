#!/bin/bash
# Test replace mode functionality

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DATA="$SCRIPT_DIR/test_data"
IMPLEMENTATION="$1"  # "python" or "go"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "========================================="
echo "Testing: Replace Mode ($IMPLEMENTATION)"
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

# Create temporary test file
TEMP_FILE=$(mktemp)
cp "$TEST_DATA/replace_test.txt" "$TEMP_FILE"

echo "Test file: $TEMP_FILE"

# Test 1: Verify original file has secrets
echo ""
echo "Test 1: Verifying original file contains secrets..."
if grep -q "mysecret123" "$TEMP_FILE" && grep -q "sk_test_abcdefg12345" "$TEMP_FILE"; then
    echo -e "${GREEN}✓ PASS${NC}: Original file contains secrets"
else
    echo -e "${RED}✗ FAIL${NC}: Original file missing expected secrets"
    rm "$TEMP_FILE"
    exit 1
fi

# Test 2: Run replace mode
echo ""
echo "Test 2: Running replace mode..."
set +e  # Temporarily disable exit on error
if [ "$IMPLEMENTATION" = "python" ]; then
    $CMD "$TEMP_FILE" --replace >/dev/null 2>&1
    EXIT_CODE=$?
else
    $CMD --replace "$TEMP_FILE" >/dev/null 2>&1
    EXIT_CODE=$?
fi
set -euo pipefail  # Re-enable
if [ $EXIT_CODE -eq 1 ]; then
    echo -e "${GREEN}✓ PASS${NC}: Replace mode executed (exit code 1)"
else
    echo -e "${RED}✗ FAIL${NC}: Expected exit code 1, got $EXIT_CODE"
    rm "$TEMP_FILE"
    exit 1
fi

# Test 3: Verify secrets were replaced with asterisks
echo ""
echo "Test 3: Verifying secrets replaced with asterisks..."
if grep -q '\*\*\*\*\*\*\*\*' "$TEMP_FILE"; then
    echo -e "${GREEN}✓ PASS${NC}: Secrets replaced with asterisks"
else
    echo -e "${RED}✗ FAIL${NC}: Secrets NOT replaced with asterisks"
    echo "File contents:"
    cat "$TEMP_FILE"
    rm "$TEMP_FILE"
    exit 1
fi

# Test 4: Verify original secrets are gone
echo ""
echo "Test 4: Verifying original secrets removed..."
if ! grep -q "mysecret123" "$TEMP_FILE" && ! grep -q "sk_test_abcdefg12345" "$TEMP_FILE"; then
    echo -e "${GREEN}✓ PASS${NC}: Original secrets removed"
else
    echo -e "${RED}✗ FAIL${NC}: Original secrets still present"
    echo "File contents:"
    cat "$TEMP_FILE"
    rm "$TEMP_FILE"
    exit 1
fi

# Test 5: Verify file has correct number of lines
echo ""
echo "Test 5: Verifying file line count preserved..."
LINE_COUNT=$(wc -l < "$TEMP_FILE")
if [ "$LINE_COUNT" -eq 4 ]; then
    echo -e "${GREEN}✓ PASS${NC}: File line count preserved (4 lines)"
else
    echo -e "${RED}✗ FAIL${NC}: File line count changed (expected 4, got $LINE_COUNT)"
    echo "File contents:"
    cat "$TEMP_FILE"
    rm "$TEMP_FILE"
    exit 1
fi

# Cleanup
rm "$TEMP_FILE"

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}All replace mode tests passed!${NC}"
echo -e "${GREEN}=========================================${NC}"
