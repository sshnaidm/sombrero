package main

import (
	"math"
	"regexp"
	"sort"
	"strings"
)

// Finding represents a detected sensitive data finding
type Finding struct {
	FilePath    string
	LineNumber  int
	PatternType string
	MatchedText string
	LineContent string
	StartPos    int
	EndPos      int
}

// Detector is the main detector class for finding sensitive data patterns
type Detector struct {
	Patterns         map[string]*regexp.Regexp
	AllowList        *AllowList
	EnableEntropy    bool
	EntropyThreshold float64
}

// NewDetector creates a new Detector instance
func NewDetector(patternTypes []string, allowList *AllowList, enableEntropy bool, entropyThreshold float64) *Detector {
	patterns := compilePatterns(patternTypes)
	return &Detector{
		Patterns:         patterns,
		AllowList:        allowList,
		EnableEntropy:    enableEntropy,
		EntropyThreshold: entropyThreshold,
	}
}

// compilePatterns compiles regex patterns for efficient matching
func compilePatterns(patternTypes []string) map[string]*regexp.Regexp {
	allPatterns := GetAllPatterns()
	compiled := make(map[string]*regexp.Regexp)

	if len(patternTypes) > 0 {
		// Filter to only requested pattern types
		for _, pt := range patternTypes {
			if pattern, exists := allPatterns[pt]; exists {
				compiled[pt] = regexp.MustCompile(pattern)
			}
		}
	} else {
		// Compile all patterns
		for name, pattern := range allPatterns {
			compiled[name] = regexp.MustCompile(pattern)
		}
	}

	return compiled
}

// CalculateEntropy calculates Shannon entropy of a string
func CalculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0.0
	}

	// Count character frequencies
	charCounts := make(map[rune]int)
	for _, char := range data {
		charCounts[char]++
	}

	// Calculate Shannon entropy
	entropy := 0.0
	dataLen := float64(len(data))

	for _, count := range charCounts {
		probability := float64(count) / dataLen
		if probability > 0 {
			entropy -= probability * math.Log2(probability)
		}
	}

	return entropy
}

// checkEntropy checks if text has high entropy (likely random/secret)
func (d *Detector) checkEntropy(text string) bool {
	if !d.EnableEntropy {
		return false
	}

	// Skip if too short or too long
	if len(text) < 20 || len(text) > 200 {
		return false
	}

	// Calculate entropy
	entropy := CalculateEntropy(text)

	return entropy >= d.EntropyThreshold
}

// ScanLine scans a single line for sensitive data
func (d *Detector) ScanLine(line string, lineNumber int, filePath string) []Finding {
	findings := make([]Finding, 0)

	// Check if entire line should be skipped
	if d.AllowList.ShouldSkipLine(line) {
		return findings
	}

	for patternType, compiledPattern := range d.Patterns {
		matches := compiledPattern.FindAllStringIndex(line, -1)

		for _, match := range matches {
			matchedText := line[match[0]:match[1]]

			// Check if this match is in the allowlist
			if d.AllowList.IsAllowed(matchedText) {
				continue
			}

			// For high-entropy patterns, verify with entropy check
			highEntropyPatterns := map[string]bool{
				"base64_string":      true,
				"hex_string":         true,
				"raw_api_key_format": true,
			}

			if highEntropyPatterns[patternType] {
				// If entropy detection is enabled, verify the entropy
				if d.EnableEntropy {
					if !d.checkEntropy(matchedText) {
						continue
					}
				} else {
					// Skip these patterns if entropy detection is not enabled
					continue
				}
			}

			finding := Finding{
				FilePath:    filePath,
				LineNumber:  lineNumber,
				PatternType: patternType,
				MatchedText: matchedText,
				LineContent: strings.TrimRight(line, "\n\r"),
				StartPos:    match[0],
				EndPos:      match[1],
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// RedactLine redacts sensitive data from a line by replacing with asterisks
func RedactLine(line string, findings []Finding) string {
	if len(findings) == 0 {
		return line
	}

	// Sort findings by position (reverse) to maintain positions during replacement
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].StartPos > findings[j].StartPos
	})

	result := []rune(line)
	for _, finding := range findings {
		// Replace with asterisks
		replacement := strings.Repeat("*", len(finding.MatchedText))
		result = []rune(string(result[:finding.StartPos]) + replacement + string(result[finding.EndPos:]))
	}

	return string(result)
}
