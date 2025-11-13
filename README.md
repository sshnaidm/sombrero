# SecScript - Security Data Leak Detection Tool

Fast, simple scanner to detect and redact sensitive technical data in files and directories. Prevents accidental exposure of credentials, API keys, and internal infrastructure details in logs, configs, and source code.

## Features

- **Pattern Detection** - Passwords, API keys, SSH keys, database credentials, internal IPs, tokens
- **Entropy Detection** - Find unlabeled secrets via Shannon entropy (base64, hex, high-entropy strings)
- **Allowlist Support** - Exclude known false positives with exact matches or regex patterns
- **Dual Modes** - Dry-run (report only) or replace (redact with asterisks)
- **Performance** - Streams files line-by-line, skips binaries, handles large directories
- **Two Implementations** - Python (single file, no dependencies) and Go (single binary)

## Quick Start

### Python Version

```bash
# Scan a file (dry-run mode)
python3 secscript.py config.txt --dry-run

# Scan directory with entropy detection
python3 secscript.py ./logs --dry-run --enable-entropy

# Replace secrets with asterisks
python3 secscript.py config.txt --replace
```

### Go Version

```bash
# Build the binary
cd go
go build -o ../secscript-go

# Scan a file (flags MUST come before path)
cd ..
./secscript-go --dry-run config.txt

# Scan directory with entropy detection
./secscript-go --dry-run --enable-entropy ./logs
```

**Important:** Go version requires flags **before** the path argument.

## Installation

### Python
- **Requirements:** Python 3.6+, no external dependencies
- **Install:** Just copy `secscript.py`

```bash
chmod +x secscript.py
python3 secscript.py --help
```

### Go
- **Requirements:** Go 1.18+ to build
- **Build:**

```bash
# Initialize Go module (first time only)
go mod init secscript

# Build from go directory
cd go
go build -o ../secscript-go
cd ..

# Run
./secscript-go --help
```

## Usage

### Common Commands

```bash
# List all pattern types
python3 secscript.py --list-patterns .
./secscript-go --list-patterns

# Dry run (detect only, no changes)
python3 secscript.py ./src --dry-run
./secscript-go --dry-run ./src

# Replace mode (redact secrets)
python3 secscript.py config.txt --replace
./secscript-go --replace config.txt

# Scan with entropy detection (finds unlabeled secrets)
python3 secscript.py ./logs -d --enable-entropy
./secscript-go -d --enable-entropy ./logs

# Specific patterns only
python3 secscript.py . -d -p password,aws_access_key,internal_ip_10
./secscript-go -d -p password,aws_access_key,internal_ip_10 .

# Save report to file
python3 secscript.py . -d -o report.txt
./secscript-go -d -o report.txt .

# Exclude files/directories
python3 secscript.py . -d --exclude "*.log" --exclude "test_*"
./secscript-go -d --exclude "*.log" --exclude "test_*" .
```

## Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--dry-run` | `-d` | Show findings without modifying files |
| `--replace` | `-r` | Replace secrets with asterisks |
| `--output FILE` | `-o` | Write output to file |
| `--pattern-types TYPES` | `-p` | Comma-separated pattern types to check |
| `--enable-entropy` | - | Detect unlabeled secrets via entropy |
| `--entropy-threshold N` | - | Shannon entropy threshold (default: 4.5) |
| `--allowlist FILE` | - | Allowlist file path (optional, default: `.secscript-allowlist` if exists) |
| `--exclude PATTERN` | - | File patterns to exclude (repeatable) |
| `--recursive` | - | Scan directories recursively (default: true) |
| `--list-patterns` | - | List all available pattern types |

## Detected Patterns

Run `python3 secscript.py --list-patterns .` or `./secscript-go --list-patterns` to see all available pattern types.

**Pattern Categories:**

- **Credentials:** `password` (matches: password, passwd, pwd, pass), `db_password`, `secret_key`, `private_key`
- **API Keys:** `aws_access_key`, `github_token`, `slack_token`, `generic_api_key`
- **Tokens:** `jwt_token`, `bearer_token`, `access_token`
- **SSH Keys:** `ssh_private_key` (detects RSA, DSA, EC, OpenSSH, PKCS#8 private keys)
- **Database:** `db_connection` (PostgreSQL, MySQL, MongoDB, Redis, JDBC connection strings)
- **Network:** `internal_ip_10` (10.x.x.x), `internal_ip_192` (192.168.x.x), `internal_ip_172` (172.16-31.x.x)
- **Identity:** `username`, `email`
- **High-Entropy** (requires `--enable-entropy`): `base64_string`, `hex_string`, `raw_api_key_format`

## Managing False Positives

The `.secscript-allowlist` file is **optional**. If not specified on command line, the tool checks for `.secscript-allowlist` in the current directory and loads it if it exists.

Create a `.secscript-allowlist` file in your working directory:

```
# Exact string match
noreply@company.com

# Regex pattern (prefix with 'regex:')
regex:.*@company\.com$
regex:^test_.*

# Skip entire lines (prefix with 'line_skip:')
line_skip:"kind":"Event"
line_skip:[DEBUG]

# Example: Allow specific token patterns
regex:^0-[A-Za-z0-9]{38,42}$
```

**How Allowlist Works:**

- **Optional**: No need to specify `--allowlist` if using default `.secscript-allowlist` file
- Lines starting with `#` are comments
- Plain text = exact match (also matches as substring)
- Lines starting with `regex:` are treated as regex patterns
- Lines starting with `line_skip:` skip entire lines containing that string (substring match)
- `regex:` patterns match the **extracted secret**, not the full line
- `line_skip:` patterns match the **entire line content** and skip scanning it

## Exit Codes

- `0` - No secrets found
- `1` - Secrets detected
- `2` - Error (invalid arguments)

Useful for CI/CD integration:

```bash
python3 secscript.py . --dry-run
if [ $? -eq 1 ]; then
    echo "ERROR: Secrets detected!"
    exit 1
fi
```

## Examples

### Example 1: Scan Source Code

```bash
# Python
python3 secscript.py ./src -d -o findings.txt

# Go
./secscript-go -d -o findings.txt ./src
```

### Example 2: Find High-Entropy Secrets in Logs

```bash
# Python
python3 secscript.py ./logs -d --enable-entropy --entropy-threshold 5.0

# Go
./secscript-go -d --enable-entropy --entropy-threshold 5.0 ./logs
```

### Example 3: Clean Config Files

```bash
# IMPORTANT: Backup first!
cp config.yaml config.yaml.backup

# Python - replace secrets
python3 secscript.py config.yaml --replace

# Go - replace secrets
./secscript-go --replace config.yaml
```

### Example 4: Scan Specific Pattern Types Only

```bash
# Look for only AWS keys and passwords
python3 secscript.py . -d -p aws_access_key,password
./secscript-go -d -p aws_access_key,password .
```

## Project Structure

```
secscript/
├── secscript.py              # Python implementation
├── go/                       # Go implementation
│   ├── main.go              # CLI and orchestration
│   ├── detector.go          # Pattern detection and entropy
│   ├── scanner.go           # File system operations
│   ├── patterns.go          # Pattern definitions
│   └── allowlist.go         # Allowlist management
├── tests/                    # Test suite
│   ├── run_all_tests.sh     # Main test runner
│   ├── test_patterns.sh     # Pattern detection tests
│   ├── test_allowlist.sh    # Allowlist tests
│   ├── test_line_skip.sh    # Line skip tests
│   ├── test_entropy.sh      # Entropy tests
│   ├── test_replace.sh      # Replace mode tests
│   ├── test_data/           # Test data files
│   └── README.md            # Test documentation
├── .github/workflows/        # GitHub Actions
│   ├── test-python.yml      # Python testing
│   ├── test-go.yml          # Go testing
│   └── test-compatibility.yml # Compatibility testing
├── go.mod                   # Go module file
├── secscript-go             # Go binary (after build)
├── .secscript-allowlist     # Default allowlist (optional)
├── ALLOWLIST.md             # Allowlist documentation
├── CLAUDE.md                # Development guide for Claude Code
├── LICENSE                  # License file
└── README.md                # This file
```

## CI/CD Integration

This repository includes comprehensive GitHub Actions workflows that use reusable test scripts:

**Automated Testing**:
- `test-python.yml` - Tests Python 3.8-3.12 (runs `./tests/run_all_tests.sh python`)
- `test-go.yml` - Tests Go 1.19-1.22 (builds binary, runs `./tests/run_all_tests.sh go`)
- `test-compatibility.yml` - Compares Python and Go outputs with 5 comprehensive tests and detailed error reporting to ensure identical results

**Local Testing**:
```bash
# Test Python implementation
./tests/run_all_tests.sh python

# Test Go implementation
./tests/run_all_tests.sh go

# Both should pass all 34 test cases (5 test suites)
```

### GitLab CI

```yaml
security-scan:
  script:
    - python3 secscript.py . -d -o security-report.txt
    - if [ $? -eq 1 ]; then exit 1; fi
  artifacts:
    paths:
      - security-report.txt
    expire_in: 30 days
    when: always
```

### GitHub Actions

```yaml
- name: Scan for secrets
  run: |
    python3 secscript.py . -d
    if [ $? -eq 1 ]; then
      echo "::error::Secrets detected!"
      exit 1
    fi
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit
python3 /path/to/secscript.py . -d --exclude ".git/*"
if [ $? -eq 1 ]; then
    echo "ERROR: Secrets detected! Commit aborted."
    exit 1
fi
```

## FAQ

**Q: What's the difference between Python and Go versions?**
A: Both produce identical results. Python is a single file with no dependencies. Go compiles to a single binary. Choose based on your deployment environment.

**Q: Why do I need `--enable-entropy`?**
A: High-entropy patterns (`base64_string`, `hex_string`, `raw_api_key_format`) can generate many false positives, so they only activate when entropy detection is explicitly enabled.

**Q: How does the allowlist work?**
A: The allowlist matches against the **detected secret** (e.g., `"secret123"`), not the entire line (e.g., `password = "secret123"`). Use exact matches for specific values or `regex:` prefix for patterns.

**Q: Can I scan only specific file types?**
A: Use `--exclude` to skip unwanted files:
`python3 secscript.py . -d --exclude "*.md" --exclude "*.log"`

**Q: Does this verify if secrets are valid?**
A: No. This tool only detects patterns. It doesn't verify if credentials are active or valid.

**Q: Are SSL certificates detected as secrets?**
A: No. Only private keys (`-----BEGIN PRIVATE KEY-----`) are detected. Public certificates (`-----BEGIN CERTIFICATE-----`) are safe to share.

## Security Notes

**What This Tool Does:**
- ✅ Detects patterns that look like secrets
- ✅ Helps prevent accidental exposure
- ✅ Works offline, no external calls

**What This Tool Does NOT Do:**
- ❌ Verify if credentials are valid
- ❌ Detect all possible secret formats
- ❌ Understand context (test vs production)
- ❌ Use AI/ML (simple regex + entropy)

**If You Find Real Secrets:**
1. ⚠️ **Rotate them immediately**
2. 🔍 Remove from git history if committed (use `git filter-repo` or BFG)
3. 📋 Audit who had access
4. 🔒 Update allowlist or patterns to prevent recurrence

## Contributing

To add new patterns:

1. **Python**: Edit `_get_all_patterns()` in `secscript.py`
2. **Go**: Edit `GetAllPatterns()` in `go/patterns.go`
3. Test with sample data
4. Ensure both implementations produce identical results

Example:
```python
# In secscript.py _get_all_patterns():
'new_pattern': r'your_regex_here',
```

```go
// In go/patterns.go GetAllPatterns():
"new_pattern": `your_regex_here`,
```

## License

Open source - use freely for security purposes. See LICENSE file.

## Quick Reference

```bash
# PYTHON
python3 secscript.py --list-patterns .     # List all patterns
python3 secscript.py file.txt -d           # Scan file
python3 secscript.py ./dir -d              # Scan directory
python3 secscript.py . -d --enable-entropy # Scan with entropy
python3 secscript.py file.txt -r           # Replace secrets

# GO (flags before path!)
./secscript-go --list-patterns             # List all patterns
./secscript-go -d file.txt                 # Scan file
./secscript-go -d ./dir                    # Scan directory
./secscript-go -d --enable-entropy .       # Scan with entropy
./secscript-go -r file.txt                 # Replace secrets
```
