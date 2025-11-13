# SecScript Test Suite

Comprehensive test suite for both Python and Go implementations.

## Test Structure

```
tests/
├── run_all_tests.sh          # Main test runner
├── test_patterns.sh           # Test all pattern detection
├── test_allowlist.sh          # Test allowlist functionality
├── test_line_skip.sh          # Test line skip feature
├── test_entropy.sh            # Test entropy detection
├── test_replace.sh            # Test replace mode
├── test_data/                 # Test data files
│   ├── all_patterns.txt       # Comprehensive pattern test file
│   ├── clean_file.txt         # File with no secrets
│   ├── line_skip_test.txt     # Line skip test scenarios
│   ├── entropy_test.txt       # High-entropy strings
│   ├── replace_test.txt       # File for replace mode testing
│   ├── allowlist_test         # Test allowlist configuration
│   └── line_skip_allowlist    # Line skip allowlist configuration
└── README.md                  # This file
```

## Usage

### Run All Tests

```bash
# Test Python implementation
./tests/run_all_tests.sh python

# Test Go implementation
./tests/run_all_tests.sh go
```

### Run Individual Tests

```bash
# Test pattern detection
./tests/test_patterns.sh python
./tests/test_patterns.sh go

# Test allowlist
./tests/test_allowlist.sh python
./tests/test_allowlist.sh go

# Test line skip
./tests/test_line_skip.sh python
./tests/test_line_skip.sh go

# Test entropy detection
./tests/test_entropy.sh python
./tests/test_entropy.sh go

# Test replace mode
./tests/test_replace.sh python
./tests/test_replace.sh go
```

## Test Coverage

### Pattern Detection (test_patterns.sh)
- ✅ All 21 pattern types
- ✅ Exit codes (0 for clean, 1 for secrets)
- ✅ Password patterns
- ✅ API keys (AWS, GitHub, Slack)
- ✅ Tokens (JWT, Bearer)
- ✅ SSH private keys
- ✅ Database connections
- ✅ Internal IPs
- ✅ Usernames/emails
- ✅ Secret keys

### Allowlist (test_allowlist.sh)
- ✅ Exact match exclusion
- ✅ Regex pattern exclusion
- ✅ Allowlist loading
- ✅ Selective exclusion

### Line Skip (test_line_skip.sh)
- ✅ Line skip pattern loading
- ✅ Event lines skipped
- ✅ DEBUG lines skipped
- ✅ Normal lines scanned
- ✅ INFO lines scanned
- ✅ ConfigMap lines scanned

### Entropy Detection (test_entropy.sh)
- ✅ Base64 pattern detection
- ✅ Hex pattern detection
- ✅ Raw API key format detection
- ✅ Entropy flag behavior

### Replace Mode (test_replace.sh)
- ✅ Secrets replaced with asterisks
- ✅ Original secrets removed
- ✅ File structure preserved
- ✅ Exit codes correct

## CI/CD Integration

These tests are used in GitHub Actions workflows:

- `.github/workflows/test-python.yml` - Runs tests on Python 3.8-3.12
- `.github/workflows/test-go.yml` - Runs tests on Go 1.19-1.22
- `.github/workflows/test-compatibility.yml` - Compares Python and Go outputs

## Test Data

### all_patterns.txt
Comprehensive test file covering all 21 pattern types including:
- Passwords (various formats)
- API keys (AWS, GitHub, Slack, generic)
- Tokens (JWT, Bearer, Access)
- SSH private keys (RSA, OPENSSH, PKCS#8)
- Database connection strings
- Internal IPs (10.x, 192.168.x, 172.16-31.x)
- Usernames and emails
- Secret keys
- High-entropy strings (for entropy detection)

### clean_file.txt
File with no secrets, used to test exit code 0.

### line_skip_test.txt
File with mixed content:
- Lines that should be skipped (Event, DEBUG)
- Lines that should be scanned (normal, INFO, ConfigMap)

### entropy_test.txt
File with high-entropy strings:
- Base64 encoded secrets
- Hex strings
- Raw API key formats

### replace_test.txt
File for testing replace mode with known secrets.

## Adding New Tests

To add a new test:

1. Create test script: `tests/test_newfeature.sh`
2. Follow the template from existing tests
3. Add to `run_all_tests.sh`
4. Update this README

## Exit Codes

- `0` - All tests passed
- `1` - One or more tests failed
- `2` - Usage error (missing arguments)
