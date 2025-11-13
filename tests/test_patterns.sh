#!/bin/bash
# Test all pattern detection

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DATA="$SCRIPT_DIR/test_data"
IMPLEMENTATION="$1"  # "python" or "go"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "Testing: Pattern Detection ($IMPLEMENTATION)"
echo "========================================="

# Set command based on implementation
if [ "$IMPLEMENTATION" = "python" ]; then
    CMD="python3 secscript.py"
elif [ "$IMPLEMENTATION" = "go" ]; then
    CMD="./secscript-go --dry-run"
else
    echo "Error: Must specify 'python' or 'go' as first argument"
    exit 2
fi

# Test 1: All patterns detection
echo ""
echo "Test 1: Detecting all pattern types..."
set +e  # Temporarily disable exit on error
# Run from test_data directory to avoid loading default allowlist
if [ "$IMPLEMENTATION" = "python" ]; then
    OUTPUT=$(cd "$TEST_DATA" && python3 ../../secscript.py all_patterns.txt --dry-run 2>&1)
    EXIT_CODE=$?
else
    OUTPUT=$(cd "$TEST_DATA" && ../../secscript-go --dry-run all_patterns.txt 2>&1)
    EXIT_CODE=$?
fi
set -euo pipefail  # Re-enable exit on error

if [ $EXIT_CODE -eq 1 ]; then
    echo -e "${GREEN}✓ PASS${NC}: Secrets detected (exit code 1)"
else
    echo -e "${RED}✗ FAIL${NC}: Expected exit code 1, got $EXIT_CODE"
    exit 1
fi

# Test 2: Verify password patterns
echo ""
echo "Test 2: Verifying password patterns..."
if echo "$OUTPUT" | grep -q "password"; then
    echo -e "${GREEN}✓ PASS${NC}: Password patterns detected"
else
    echo -e "${RED}✗ FAIL${NC}: Password patterns NOT detected"
    exit 1
fi

# Test 3: Verify API key patterns
echo ""
echo "Test 3: Verifying API key patterns..."
if echo "$OUTPUT" | grep -qE "aws_access_key|github_token|slack_token|generic_api_key"; then
    echo -e "${GREEN}✓ PASS${NC}: API key patterns detected"
else
    echo -e "${RED}✗ FAIL${NC}: API key patterns NOT detected"
    exit 1
fi

# Test 4: Verify token patterns
echo ""
echo "Test 4: Verifying token patterns..."
if echo "$OUTPUT" | grep -qE "jwt_token|bearer_token"; then
    echo -e "${GREEN}✓ PASS${NC}: Token patterns detected"
else
    echo -e "${RED}✗ FAIL${NC}: Token patterns NOT detected"
    exit 1
fi

# Test 5: Verify SSH key patterns
echo ""
echo "Test 5: Verifying SSH key patterns..."
if echo "$OUTPUT" | grep -q "ssh_private_key"; then
    echo -e "${GREEN}✓ PASS${NC}: SSH private key patterns detected"
else
    echo -e "${RED}✗ FAIL${NC}: SSH private key patterns NOT detected"
    exit 1
fi

# Test 6: Verify database connection patterns
echo ""
echo "Test 6: Verifying database connection patterns..."
if echo "$OUTPUT" | grep -q "db_connection"; then
    echo -e "${GREEN}✓ PASS${NC}: Database connection patterns detected"
else
    echo -e "${RED}✗ FAIL${NC}: Database connection patterns NOT detected"
    exit 1
fi

# Test 7: Verify internal IP patterns
echo ""
echo "Test 7: Verifying internal IP patterns..."
if echo "$OUTPUT" | grep -qE "internal_ip"; then
    echo -e "${GREEN}✓ PASS${NC}: Internal IP patterns detected"
else
    echo -e "${RED}✗ FAIL${NC}: Internal IP patterns NOT detected"
    exit 1
fi

# Test 8: Verify username/email patterns
echo ""
echo "Test 8: Verifying username/email patterns..."
if echo "$OUTPUT" | grep -qE "username|email"; then
    echo -e "${GREEN}✓ PASS${NC}: Username/email patterns detected"
else
    echo -e "${RED}✗ FAIL${NC}: Username/email patterns NOT detected"
    exit 1
fi

# Test 9: Verify secret key patterns
echo ""
echo "Test 9: Verifying secret key patterns..."
if echo "$OUTPUT" | grep -qE "secret_key|private_key|access_token"; then
    echo -e "${GREEN}✓ PASS${NC}: Secret key patterns detected"
else
    echo -e "${RED}✗ FAIL${NC}: Secret key patterns NOT detected"
    exit 1
fi

# Test 10: Clean file (no secrets)
echo ""
echo "Test 10: Testing clean file (no secrets)..."
set +e  # Temporarily disable exit on error
# Run from test_data directory to avoid loading default allowlist
if [ "$IMPLEMENTATION" = "python" ]; then
    cd "$TEST_DATA" && python3 ../../secscript.py clean_file.txt --dry-run >/dev/null 2>&1
    EXIT_CODE=$?
    cd - >/dev/null
else
    cd "$TEST_DATA" && ../../secscript-go --dry-run clean_file.txt >/dev/null 2>&1
    EXIT_CODE=$?
    cd - >/dev/null
fi
set -euo pipefail  # Re-enable exit on error

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ PASS${NC}: No secrets detected (exit code 0)"
else
    echo -e "${RED}✗ FAIL${NC}: Expected exit code 0, got $EXIT_CODE"
    exit 1
fi

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}All pattern detection tests passed!${NC}"
echo -e "${GREEN}=========================================${NC}"
