package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// Scanner handles file and directory scanning operations
type Scanner struct {
	Detector        *Detector
	ExcludePatterns []string
	BinaryExts      map[string]bool
}

// NewScanner creates a new Scanner instance
func NewScanner(detector *Detector, excludePatterns []string) *Scanner {
	binaryExts := map[string]bool{
		".pyc": true, ".so": true, ".dll": true, ".exe": true, ".bin": true,
		".jar": true, ".class": true, ".png": true, ".jpg": true, ".jpeg": true,
		".gif": true, ".pdf": true, ".zip": true, ".tar": true, ".gz": true,
	}

	return &Scanner{
		Detector:        detector,
		ExcludePatterns: excludePatterns,
		BinaryExts:      binaryExts,
	}
}

// IsBinaryFile checks if file is likely binary
func (s *Scanner) IsBinaryFile(filePath string) bool {
	// Check extension first
	ext := strings.ToLower(filepath.Ext(filePath))
	if s.BinaryExts[ext] {
		return true
	}

	// Read first 8192 bytes and check for null bytes
	file, err := os.Open(filePath)
	if err != nil {
		return true
	}
	defer file.Close()

	buf := make([]byte, 8192)
	n, err := file.Read(buf)
	if err != nil && n == 0 {
		return true
	}

	return bytes.Contains(buf[:n], []byte{0})
}

// ShouldExclude checks if path matches any exclude pattern
func (s *Scanner) ShouldExclude(path string) bool {
	for _, pattern := range s.ExcludePatterns {
		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err == nil && matched {
			return true
		}
	}
	return false
}

// ScanFileResult holds the results of scanning a file
type ScanFileResult struct {
	Findings        []Finding
	ModifiedContent string
}

// ScanFile scans a single file for sensitive data
func (s *Scanner) ScanFile(filePath string, dryRun bool) (*ScanFileResult, error) {
	findings := make([]Finding, 0)
	var modifiedLines []string

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text() + "\n"

		lineFindings := s.Detector.ScanLine(line, lineNumber, filePath)
		findings = append(findings, lineFindings...)

		if !dryRun {
			if len(lineFindings) > 0 {
				// Redact the line
				modifiedLine := RedactLine(line, lineFindings)
				modifiedLines = append(modifiedLines, modifiedLine)
			} else {
				modifiedLines = append(modifiedLines, line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	result := &ScanFileResult{
		Findings: findings,
	}

	if !dryRun {
		result.ModifiedContent = strings.Join(modifiedLines, "")
	}

	return result, nil
}

// ScanDirectory scans directory for sensitive data
func (s *Scanner) ScanDirectory(directory string, recursive bool, dryRun bool) (map[string]*ScanFileResult, error) {
	results := make(map[string]*ScanFileResult)

	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip if not recursive and not in root directory
		if !recursive && filepath.Dir(path) != directory {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check exclusion patterns
		if s.ShouldExclude(path) {
			return nil
		}

		// Check if binary
		if s.IsBinaryFile(path) {
			return nil
		}

		// Scan the file
		result, err := s.ScanFile(path, dryRun)
		if err != nil {
			// Continue on error, just log it
			return nil
		}

		if len(result.Findings) > 0 {
			results[path] = result
		}

		return nil
	})

	return results, err
}
