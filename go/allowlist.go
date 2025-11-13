package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// AllowList manages allowlist/exclusions for false positive handling
type AllowList struct {
	ExactMatches     []string
	RegexPatterns    []*regexp.Regexp
	LineSkipPatterns []string
}

// NewAllowList creates a new AllowList from a file
func NewAllowList(filePath string) (*AllowList, error) {
	al := &AllowList{
		ExactMatches:     make([]string, 0),
		RegexPatterns:    make([]*regexp.Regexp, 0),
		LineSkipPatterns: make([]string, 0),
	}

	if filePath == "" {
		return al, nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return al, nil
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if it's a line skip pattern (prefixed with 'line_skip:')
		if strings.HasPrefix(line, "line_skip:") {
			skipStr := strings.TrimSpace(line[10:])
			al.LineSkipPatterns = append(al.LineSkipPatterns, skipStr)
		} else if strings.HasPrefix(line, "regex:") {
			// Check if it's a regex pattern (prefixed with 'regex:')
			patternStr := strings.TrimSpace(line[6:])
			compiled, err := regexp.Compile(patternStr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Invalid regex pattern at line %d: %v\n", lineNum, err)
				continue
			}
			al.RegexPatterns = append(al.RegexPatterns, compiled)
		} else {
			// Exact match
			al.ExactMatches = append(al.ExactMatches, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return al, nil
}

// ShouldSkipLine checks if entire line should be skipped from scanning
func (al *AllowList) ShouldSkipLine(line string) bool {
	for _, skipPattern := range al.LineSkipPatterns {
		if strings.Contains(line, skipPattern) {
			return true
		}
	}
	return false
}

// IsAllowed checks if a matched text should be allowed (excluded from findings)
func (al *AllowList) IsAllowed(text string) bool {
	// Check exact matches - both exact equality and substring matching
	for _, exactMatch := range al.ExactMatches {
		if text == exactMatch || strings.Contains(text, exactMatch) {
			return true
		}
	}

	// Check regex patterns
	for _, pattern := range al.RegexPatterns {
		if pattern.MatchString(text) {
			return true
		}
	}

	return false
}
