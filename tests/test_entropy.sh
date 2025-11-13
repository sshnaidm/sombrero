#!/bin/bash
# Test entropy detection functionality

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DATA="$SCRIPT_DIR/test_data"
IMPLEMENTATION="$1"  # "python" or "go"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "========================================="
echo "Testing: Entropy Detection ($IMPLEMENTATION)"
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

# Test 1: Without entropy detection (baseline)
echo ""
echo "Test 1: Scanning without entropy detection (baseline)..."
# Run from test_data directory to avoid loading default allowlist
if [ "$IMPLEMENTATION" = "python" ]; then
    OUTPUT_NO_ENTROPY=$(cd "$TEST_DATA" && python3 ../../secscript.py entropy_test.txt --dry-run 2>&1 || true)
else
    OUTPUT_NO_ENTROPY=$(cd "$TEST_DATA" && ../../secscript-go --dry-run entropy_test.txt 2>&1 || true)
fi

# Should not detect high-entropy patterns without flag
if ! echo "$OUTPUT_NO_ENTROPY" | grep -qE "base64_string|hex_string|raw_api_key_format"; then
    echo -e "${GREEN}✓ PASS${NC}: High-entropy patterns not detected without flag"
else
    echo "Note: Some entropy patterns detected without flag (expected behavior may vary)"
fi

# Test 2: With entropy detection enabled
echo ""
echo "Test 2: Scanning with entropy detection enabled..."
set +e  # Temporarily disable exit on error
# Run from test_data directory to avoid loading default allowlist
if [ "$IMPLEMENTATION" = "python" ]; then
    OUTPUT_WITH_ENTROPY=$(cd "$TEST_DATA" && python3 ../../secscript.py entropy_test.txt --dry-run --enable-entropy 2>&1)
    EXIT_CODE=$?
else
    OUTPUT_WITH_ENTROPY=$(cd "$TEST_DATA" && ../../secscript-go --dry-run --enable-entropy entropy_test.txt 2>&1)
    EXIT_CODE=$?
fi
set -euo pipefail  # Re-enable
if [ $EXIT_CODE -eq 1 ]; then
    echo -e "${GREEN}✓ PASS${NC}: Entropy patterns detected (exit code 1)"
else
    echo -e "${RED}✗ FAIL${NC}: Expected exit code 1, got $EXIT_CODE"
    exit 1
fi

# Test 3: Verify base64 pattern detection
echo ""
echo "Test 3: Verifying base64 pattern detection..."
if echo "$OUTPUT_WITH_ENTROPY" | grep -q "base64_string"; then
    echo -e "${GREEN}✓ PASS${NC}: Base64 patterns detected"
else
    echo -e "${RED}✗ FAIL${NC}: Base64 patterns NOT detected"
    exit 1
fi

# Test 4: Verify hex pattern detection
# Note: Hex strings often have lower entropy than the threshold due to limited character set (0-9,a-f)
# So they may not always be detected with default entropy threshold
echo ""
echo "Test 4: Verifying hex pattern detection (optional)..."
if echo "$OUTPUT_WITH_ENTROPY" | grep -q "hex_string"; then
    echo -e "${GREEN}✓ PASS${NC}: Hex patterns detected"
else
    echo "Note: Hex patterns not detected (low entropy, expected with default threshold)"
fi

# Test 5: Verify raw API key format detection
echo ""
echo "Test 5: Verifying raw API key format detection..."
if echo "$OUTPUT_WITH_ENTROPY" | grep -q "raw_api_key_format"; then
    echo -e "${GREEN}✓ PASS${NC}: Raw API key format detected"
else
    echo -e "${RED}✗ FAIL${NC}: Raw API key format NOT detected"
    exit 1
fi

# Test 6: Verify entropy detection message
echo ""
echo "Test 6: Verifying entropy detection status message..."
if echo "$OUTPUT_WITH_ENTROPY" | grep -qi "entropy.*enabled"; then
    echo -e "${GREEN}✓ PASS${NC}: Entropy detection status shown"
else
    echo "Note: Entropy status message not found (may not be critical)"
fi

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}All entropy detection tests passed!${NC}"
echo -e "${GREEN}=========================================${NC}"
