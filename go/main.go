package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

const version = "1.0.0"

func main() {
	// Define flags
	var (
		dryRun           bool
		replace          bool
		output           string
		patternTypesStr  string
		recursive        bool
		excludeList      stringSliceFlag
		allowlistPath    string
		enableEntropy    bool
		entropyThreshold float64
		listPatterns     bool
	)

	flag.BoolVar(&dryRun, "dry-run", false, "Show what would be replaced without modifying files")
	flag.BoolVar(&dryRun, "d", false, "Shorthand for --dry-run")
	flag.BoolVar(&replace, "replace", false, "Replace sensitive data with asterisks in files")
	flag.BoolVar(&replace, "r", false, "Shorthand for --replace")
	flag.StringVar(&output, "output", "", "Write output to file instead of STDOUT")
	flag.StringVar(&output, "o", "", "Shorthand for --output")
	flag.StringVar(&patternTypesStr, "pattern-types", "", "Comma-separated list of pattern types to check")
	flag.StringVar(&patternTypesStr, "p", "", "Shorthand for --pattern-types")
	flag.BoolVar(&recursive, "recursive", true, "Scan directories recursively (default: true)")
	flag.Var(&excludeList, "exclude", "Patterns to exclude (can be specified multiple times)")
	flag.StringVar(&allowlistPath, "allowlist", "", "Path to allowlist file (default: .secscript-allowlist if it exists)")
	flag.BoolVar(&enableEntropy, "enable-entropy", false, "Enable entropy-based detection for unlabeled secrets")
	flag.Float64Var(&entropyThreshold, "entropy-threshold", 4.5, "Shannon entropy threshold (default: 4.5, range: 0-8)")
	flag.BoolVar(&listPatterns, "list-patterns", false, "List all available pattern types and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Security Data Leak Detection and Redaction Tool\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <path>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s config.py --dry-run\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s ./src --replace --recursive\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s logs/ -d -p password,api_key\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s . -d --enable-entropy\n", os.Args[0])
	}

	flag.Parse()

	// Handle list patterns
	if listPatterns {
		patterns := GetAllPatterns()
		fmt.Println("Available pattern types:")
		keys := make([]string, 0, len(patterns))
		for k := range patterns {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  - %s\n", k)
		}
		os.Exit(0)
	}

	// Validate mode
	if !dryRun && !replace {
		fmt.Fprintln(os.Stderr, "Error: Must specify either --dry-run or --replace mode")
		os.Exit(1)
	}

	if dryRun && replace {
		fmt.Fprintln(os.Stderr, "Error: Cannot specify both --dry-run and --replace")
		os.Exit(1)
	}

	// Get path argument
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: Path argument is required")
		flag.Usage()
		os.Exit(1)
	}
	path := flag.Arg(0)

	// Parse pattern types
	var patternTypes []string
	if patternTypesStr != "" {
		patternTypes = strings.Split(patternTypesStr, ",")
		for i := range patternTypes {
			patternTypes[i] = strings.TrimSpace(patternTypes[i])
		}
	}

	// Load allowlist
	// If no allowlist specified, check for default file
	if allowlistPath == "" {
		if _, err := os.Stat(".secscript-allowlist"); err == nil {
			allowlistPath = ".secscript-allowlist"
		}
	}

	allowlist, err := NewAllowList(allowlistPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading allowlist: %v\n", err)
		os.Exit(1)
	}

	if allowlistPath != "" {
		if _, err := os.Stat(allowlistPath); err == nil {
			fmt.Fprintf(os.Stderr, "Loaded allowlist from: %s\n", allowlistPath)
			fmt.Fprintf(os.Stderr, "  - %d exact matches\n", len(allowlist.ExactMatches))
			fmt.Fprintf(os.Stderr, "  - %d regex patterns\n", len(allowlist.RegexPatterns))
			fmt.Fprintf(os.Stderr, "  - %d line skip patterns\n", len(allowlist.LineSkipPatterns))
		}
	}

	// Show entropy detection status
	if enableEntropy {
		fmt.Fprintf(os.Stderr, "Entropy detection: ENABLED (threshold: %.1f)\n", entropyThreshold)
	}

	// Initialize detector and scanner
	detector := NewDetector(patternTypes, allowlist, enableEntropy, entropyThreshold)
	scanner := NewScanner(detector, excludeList)

	// Check if path exists
	fileInfo, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Path does not exist: %s\n", path)
		os.Exit(1)
	}

	// Scan path
	results := make(map[string]*ScanFileResult)

	if !fileInfo.IsDir() {
		// Single file
		result, err := scanner.ScanFile(path, dryRun)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning %s: %v\n", path, err)
			os.Exit(1)
		}
		if len(result.Findings) > 0 {
			results[path] = result
		}
	} else {
		// Directory
		results, err = scanner.ScanDirectory(path, recursive, dryRun)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning directory: %v\n", err)
			os.Exit(1)
		}
	}

	// Format output
	outputStr := formatFindings(results, dryRun)

	// Write output
	if output != "" {
		err := os.WriteFile(output, []byte(outputStr), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Results written to %s\n", output)
	} else {
		fmt.Print(outputStr)
	}

	// If replace mode, write modified files
	if replace {
		for filePath, result := range results {
			if result.ModifiedContent != "" {
				err := os.WriteFile(filePath, []byte(result.ModifiedContent), 0644)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", filePath, err)
				} else {
					fmt.Fprintf(os.Stderr, "Modified: %s\n", filePath)
				}
			}
		}
	}

	// Exit with appropriate code
	if len(results) > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

// formatFindings formats scan results for output
func formatFindings(results map[string]*ScanFileResult, dryRun bool) string {
	var sb strings.Builder
	totalFindings := 0

	// Sort file paths for consistent output
	filePaths := make([]string, 0, len(results))
	for fp := range results {
		filePaths = append(filePaths, fp)
	}
	sort.Strings(filePaths)

	for _, filePath := range filePaths {
		result := results[filePath]
		if len(result.Findings) == 0 {
			continue
		}

		sb.WriteString("\n")
		sb.WriteString(strings.Repeat("=", 80))
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("File: %s\n", filePath))
		sb.WriteString(strings.Repeat("=", 80))
		sb.WriteString("\n")

		// Group findings by line number
		byLine := make(map[int][]Finding)
		for _, finding := range result.Findings {
			byLine[finding.LineNumber] = append(byLine[finding.LineNumber], finding)
		}

		// Get sorted line numbers
		lineNumbers := make([]int, 0, len(byLine))
		for ln := range byLine {
			lineNumbers = append(lineNumbers, ln)
		}
		sort.Ints(lineNumbers)

		for _, lineNum := range lineNumbers {
			lineFindings := byLine[lineNum]
			sb.WriteString(fmt.Sprintf("\nLine %d:\n", lineNum))

			for _, finding := range lineFindings {
				sb.WriteString(fmt.Sprintf("  [%s] Found: %s\n", finding.PatternType, finding.MatchedText))
			}

			// Show the line content (truncated)
			lineContent := lineFindings[0].LineContent
			if len(lineContent) > 100 {
				lineContent = lineContent[:100] + "..."
			}
			sb.WriteString(fmt.Sprintf("  [%s] Content: %s\n", lineFindings[0].PatternType, lineContent))
			totalFindings += len(lineFindings)
		}
	}

	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("=", 80))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Total findings: %d across %d files\n", totalFindings, len(results)))
	mode := "DRY RUN - No changes made"
	if !dryRun {
		mode = "REPLACE - Files modified"
	}
	sb.WriteString(fmt.Sprintf("Mode: %s\n", mode))
	sb.WriteString(strings.Repeat("=", 80))
	sb.WriteString("\n")

	return sb.String()
}

// stringSliceFlag is a custom flag type for multiple string values
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}
