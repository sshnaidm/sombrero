#!/usr/bin/env python3
"""
Security Data Leak Detection and Redaction Tool

Detects and optionally redacts sensitive technical data from files including:
- Passwords and credentials
- API keys and tokens
- SSH private keys
- Database connection strings
- Internal IP addresses
- Usernames and emails
"""

import re
import argparse
import sys
import os
import math
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass
import mimetypes


@dataclass
class Finding:
    """Represents a detected sensitive data finding"""
    file_path: str
    line_number: int
    pattern_type: str
    matched_text: str
    line_content: str
    start_pos: int
    end_pos: int


class AllowList:
    """Manages allowlist/exclusions for false positive handling"""

    def __init__(self, allowlist_file: Optional[Path] = None):
        """Initialize allowlist from file"""
        self.exact_matches: Set[str] = set()
        self.regex_patterns: List[re.Pattern] = []
        self.line_skip_patterns: List[str] = []

        if allowlist_file and allowlist_file.exists():
            self._load_from_file(allowlist_file)

    def _load_from_file(self, file_path: Path):
        """Load allowlist entries from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, start=1):
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue

                    # Check if it's a line skip pattern (prefixed with 'line_skip:')
                    if line.startswith('line_skip:'):
                        skip_str = line[10:].strip()
                        self.line_skip_patterns.append(skip_str)
                    # Check if it's a regex pattern (prefixed with 'regex:')
                    elif line.startswith('regex:'):
                        pattern_str = line[6:].strip()
                        try:
                            compiled = re.compile(pattern_str)
                            self.regex_patterns.append(compiled)
                        except re.error as e:
                            print(f"Warning: Invalid regex pattern at line {line_num}: {e}",
                                  file=sys.stderr)
                    else:
                        # Exact match
                        self.exact_matches.add(line)
        except Exception as e:
            print(f"Error loading allowlist from {file_path}: {e}", file=sys.stderr)

    def should_skip_line(self, line: str) -> bool:
        """Check if entire line should be skipped from scanning"""
        for skip_pattern in self.line_skip_patterns:
            if skip_pattern in line:
                return True
        return False

    def is_allowed(self, text: str) -> bool:
        """Check if a matched text should be allowed (excluded from findings)"""
        # Check exact matches - both exact equality and substring matching
        if text in self.exact_matches:
            return True

        # Check if any exact match appears in the text
        for exact_match in self.exact_matches:
            if exact_match in text:
                return True

        # Check regex patterns
        for pattern in self.regex_patterns:
            if pattern.search(text):
                return True

        return False


class SensitiveDataDetector:
    """Main detector class for finding sensitive data patterns"""

    def __init__(self, pattern_types: Optional[List[str]] = None, allowlist: Optional[AllowList] = None,
                 enable_entropy: bool = False, entropy_threshold: float = 4.5):
        """Initialize detector with specified pattern types and allowlist"""
        self.patterns = self._compile_patterns(pattern_types)
        self.allowlist = allowlist or AllowList()
        self.enable_entropy = enable_entropy
        self.entropy_threshold = entropy_threshold

    def _get_all_patterns(self) -> Dict[str, str]:
        """Define all regex patterns for sensitive data detection"""
        return {
            # Passwords - common password assignments
            'password': r'(?i)(password|passwd|pwd|pass)\s*[=:]\s*["\']?([^\s"\']{3,})["\']?',

            # API Keys - AWS, GitHub, Slack, generic
            'aws_access_key': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            'github_token': r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',
            'slack_token': r'xox[pboa]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}',
            'generic_api_key': r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',

            # Tokens - JWT, OAuth, Bearer
            'jwt_token': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            'bearer_token': r'(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}',

            # SSH Private Keys (includes PKCS#8 generic format)
            'ssh_private_key': r'-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH) )?PRIVATE KEY-----',

            # Database connection strings
            'db_connection': r'(?i)(?:postgresql|mysql|mongodb|redis|jdbc):\/\/[^\s:]+:[^\s@]+@[^\s\/]+',
            'db_password': r'(?i)(?:db|database)[_-]?(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{3,})["\']?',

            # Internal IP addresses (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
            'internal_ip_10': r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'internal_ip_192': r'\b192\.168\.\d{1,3}\.\d{1,3}\b',
            'internal_ip_172': r'\b172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b',

            # Usernames and emails
            'username': r'(?i)(?:user|username|login)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.@]{3,})["\']?',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',

            # Secret keys
            'secret_key': r'(?i)(?:secret[_-]?key|secretkey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
            'private_key': r'(?i)(?:private[_-]?key|privatekey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',

            # Access tokens
            'access_token': r'(?i)(?:access[_-]?token|accesstoken)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?',

            # High-entropy / unlabeled secrets (optional, can generate false positives)
            # These detect raw keys/hashes without labels
            'base64_string': r'\b[A-Za-z0-9+/]{40,}={0,2}\b',
            'hex_string': r'\b[a-fA-F0-9]{32,}\b',
            'raw_api_key_format': r'\b[A-Za-z0-9_\-]{32,}\b',
        }

    def _compile_patterns(self, pattern_types: Optional[List[str]] = None) -> Dict[str, re.Pattern]:
        """Compile regex patterns for efficient matching"""
        all_patterns = self._get_all_patterns()

        if pattern_types:
            # Filter to only requested pattern types
            patterns_to_use = {k: v for k, v in all_patterns.items() if k in pattern_types}
        else:
            patterns_to_use = all_patterns

        # Compile all patterns for performance
        return {name: re.compile(pattern) for name, pattern in patterns_to_use.items()}

    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0.0

        # Count frequency of each character
        entropy = 0.0
        data_len = len(data)

        # Count character frequencies
        char_counts = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate Shannon entropy
        for count in char_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _check_entropy(self, text: str) -> bool:
        """Check if text has high entropy (likely random/secret)"""
        if not self.enable_entropy:
            return False

        # Skip if too short or too long
        if len(text) < 20 or len(text) > 200:
            return False

        # Calculate entropy
        entropy = self._calculate_entropy(text)

        return entropy >= self.entropy_threshold

    def scan_line(self, line: str, line_number: int, file_path: str) -> List[Finding]:
        """Scan a single line for sensitive data"""
        findings = []

        # Check if entire line should be skipped
        if self.allowlist.should_skip_line(line):
            return findings

        for pattern_type, compiled_pattern in self.patterns.items():
            for match in compiled_pattern.finditer(line):
                matched_text = match.group(0)

                # Check if this match is in the allowlist
                if self.allowlist.is_allowed(matched_text):
                    continue

                # For high-entropy patterns, verify with entropy check
                high_entropy_patterns = {'base64_string', 'hex_string', 'raw_api_key_format'}
                if pattern_type in high_entropy_patterns:
                    # If entropy detection is enabled, verify the entropy
                    if self.enable_entropy:
                        if not self._check_entropy(matched_text):
                            continue
                    else:
                        # Skip these patterns if entropy detection is not enabled
                        # to avoid too many false positives
                        continue

                finding = Finding(
                    file_path=file_path,
                    line_number=line_number,
                    pattern_type=pattern_type,
                    matched_text=matched_text,
                    line_content=line.rstrip('\n'),
                    start_pos=match.start(),
                    end_pos=match.end()
                )
                findings.append(finding)

        return findings

    def redact_line(self, line: str, findings: List[Finding]) -> str:
        """Redact sensitive data from a line by replacing with asterisks"""
        if not findings:
            return line

        # Sort findings by position (reverse) to maintain positions during replacement
        sorted_findings = sorted(findings, key=lambda f: f.start_pos, reverse=True)

        result = line
        for finding in sorted_findings:
            # Replace with asterisks
            replacement = '*' * len(finding.matched_text)
            result = result[:finding.start_pos] + replacement + result[finding.end_pos:]

        return result


class FileScanner:
    """Handles file and directory scanning operations"""

    def __init__(self, detector: SensitiveDataDetector, exclude_patterns: Optional[List[str]] = None):
        self.detector = detector
        self.exclude_patterns = exclude_patterns or []
        self.binary_extensions = {'.pyc', '.so', '.dll', '.exe', '.bin', '.jar', '.class',
                                 '.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', '.tar', '.gz'}

    def is_binary_file(self, file_path: Path) -> bool:
        """Check if file is likely binary"""
        # Check extension first
        if file_path.suffix.lower() in self.binary_extensions:
            return True

        # Check mime type
        mime_type, _ = mimetypes.guess_type(str(file_path))
        if mime_type and not mime_type.startswith('text'):
            return True

        # Read first 8192 bytes and check for null bytes
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(8192)
                return b'\x00' in chunk
        except Exception:
            return True

    def should_exclude(self, path: Path) -> bool:
        """Check if path matches any exclude pattern"""
        path_str = str(path)
        for pattern in self.exclude_patterns:
            if Path(path_str).match(pattern):
                return True
        return False

    def scan_file(self, file_path: Path, dry_run: bool = True) -> Tuple[List[Finding], Optional[str]]:
        """
        Scan a single file for sensitive data

        Returns:
            Tuple of (findings, modified_content)
            modified_content is None in dry-run mode
        """
        findings = []
        modified_lines = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_number, line in enumerate(f, start=1):
                    line_findings = self.detector.scan_line(line, line_number, str(file_path))
                    findings.extend(line_findings)

                    if not dry_run and line_findings:
                        # Redact the line
                        modified_line = self.detector.redact_line(line, line_findings)
                        modified_lines.append(modified_line)
                    elif not dry_run:
                        modified_lines.append(line)

        except Exception as e:
            print(f"Error scanning {file_path}: {e}", file=sys.stderr)
            return findings, None

        modified_content = ''.join(modified_lines) if not dry_run else None
        return findings, modified_content

    def scan_directory(self, directory: Path, recursive: bool = True,
                      dry_run: bool = True) -> Dict[str, Tuple[List[Finding], Optional[str]]]:
        """
        Scan directory for sensitive data

        Returns:
            Dict mapping file paths to (findings, modified_content) tuples
        """
        results = {}

        if recursive:
            pattern = '**/*'
        else:
            pattern = '*'

        for file_path in directory.glob(pattern):
            if not file_path.is_file():
                continue

            if self.should_exclude(file_path):
                continue

            if self.is_binary_file(file_path):
                continue

            findings, modified_content = self.scan_file(file_path, dry_run)
            if findings:
                results[str(file_path)] = (findings, modified_content)

        return results


class OutputFormatter:
    """Formats and outputs scan results"""

    @staticmethod
    def format_findings(results: Dict[str, Tuple[List[Finding], Optional[str]]],
                       dry_run: bool = True) -> str:
        """Format findings for output"""
        output_lines = []
        total_findings = 0

        for file_path, (findings, _) in sorted(results.items()):
            if not findings:
                continue

            output_lines.append(f"\n{'='*80}")
            output_lines.append(f"File: {file_path}")
            output_lines.append(f"{'='*80}")

            # Group findings by line number
            by_line = {}
            for finding in findings:
                if finding.line_number not in by_line:
                    by_line[finding.line_number] = []
                by_line[finding.line_number].append(finding)

            for line_num in sorted(by_line.keys()):
                line_findings = by_line[line_num]
                output_lines.append(f"\nLine {line_num}:")

                for finding in line_findings:
                    output_lines.append(f"  [{finding.pattern_type}] Found: {finding.matched_text}")

                # Show the line content
                output_lines.append(f"  [{finding.pattern_type}] Content: {line_findings[0].line_content[:100]}...")
                total_findings += len(line_findings)

        output_lines.append(f"\n{'='*80}")
        output_lines.append(f"Total findings: {total_findings} across {len(results)} files")
        output_lines.append(f"Mode: {'DRY RUN - No changes made' if dry_run else 'REPLACE - Files modified'}")
        output_lines.append(f"{'='*80}\n")

        return '\n'.join(output_lines)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Detect and redact sensitive technical data from files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry run on single file
  %(prog)s config.py --dry-run

  # Scan directory recursively and replace
  %(prog)s ./src --replace --recursive

  # Scan with specific patterns only
  %(prog)s logs/ -d -p password,api_key,internal_ip_10

  # Save output to file
  %(prog)s . -d -o report.txt
        """
    )

    parser.add_argument('path', help='File or directory to scan')
    parser.add_argument('-d', '--dry-run', action='store_true',
                       help='Show what would be replaced without modifying files')
    parser.add_argument('-r', '--replace', action='store_true',
                       help='Replace sensitive data with asterisks in files')
    parser.add_argument('-o', '--output', help='Write output to file instead of STDOUT')
    parser.add_argument('-p', '--pattern-types',
                       help='Comma-separated list of pattern types to check')
    parser.add_argument('--recursive', action='store_true', default=True,
                       help='Scan directories recursively (default: True)')
    parser.add_argument('--exclude', action='append',
                       help='Patterns to exclude (can be specified multiple times)')
    parser.add_argument('--allowlist', default=None,
                       help='Path to allowlist file (default: .secscript-allowlist if it exists)')
    parser.add_argument('--enable-entropy', action='store_true',
                       help='Enable entropy-based detection for unlabeled secrets (base64, hex, high-entropy strings)')
    parser.add_argument('--entropy-threshold', type=float, default=4.5,
                       help='Shannon entropy threshold for high-entropy detection (default: 4.5, range: 0-8)')
    parser.add_argument('--list-patterns', action='store_true',
                       help='List all available pattern types and exit')

    args = parser.parse_args()

    # Handle list patterns
    if args.list_patterns:
        detector = SensitiveDataDetector()
        print("Available pattern types:")
        for pattern_type in sorted(detector._get_all_patterns().keys()):
            print(f"  - {pattern_type}")
        sys.exit(0)

    # Validate mode
    if not args.dry_run and not args.replace:
        print("Error: Must specify either --dry-run or --replace mode", file=sys.stderr)
        sys.exit(1)

    if args.dry_run and args.replace:
        print("Error: Cannot specify both --dry-run and --replace", file=sys.stderr)
        sys.exit(1)

    # Parse pattern types
    pattern_types = None
    if args.pattern_types:
        pattern_types = [p.strip() for p in args.pattern_types.split(',')]

    # Load allowlist
    # If no allowlist specified, check for default file
    if args.allowlist is None:
        default_allowlist = Path('.secscript-allowlist')
        allowlist_path = default_allowlist if default_allowlist.exists() else None
    else:
        allowlist_path = Path(args.allowlist) if Path(args.allowlist).exists() else None

    allowlist = AllowList(allowlist_path)
    if allowlist_path:
        print(f"Loaded allowlist from: {allowlist_path}", file=sys.stderr)
        print(f"  - {len(allowlist.exact_matches)} exact matches", file=sys.stderr)
        print(f"  - {len(allowlist.regex_patterns)} regex patterns", file=sys.stderr)
        print(f"  - {len(allowlist.line_skip_patterns)} line skip patterns", file=sys.stderr)

    # Show entropy detection status
    if args.enable_entropy:
        print(f"Entropy detection: ENABLED (threshold: {args.entropy_threshold})", file=sys.stderr)

    # Initialize detector and scanner
    detector = SensitiveDataDetector(pattern_types, allowlist,
                                     args.enable_entropy, args.entropy_threshold)
    scanner = FileScanner(detector, args.exclude)

    # Scan path
    path = Path(args.path)
    if not path.exists():
        print(f"Error: Path does not exist: {args.path}", file=sys.stderr)
        sys.exit(1)

    results = {}
    if path.is_file():
        findings, modified_content = scanner.scan_file(path, dry_run=args.dry_run)
        if findings:
            results[str(path)] = (findings, modified_content)
    else:
        results = scanner.scan_directory(path, args.recursive, dry_run=args.dry_run)

    # Format output
    output = OutputFormatter.format_findings(results, dry_run=args.dry_run)

    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Results written to {args.output}")
    else:
        print(output)

    # If replace mode, write modified files
    if args.replace:
        for file_path, (findings, modified_content) in results.items():
            if modified_content is not None:
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(modified_content)
                    print(f"Modified: {file_path}", file=sys.stderr)
                except Exception as e:
                    print(f"Error writing {file_path}: {e}", file=sys.stderr)

    # Exit with appropriate code
    sys.exit(0 if not results else 1)


if __name__ == '__main__':
    main()
