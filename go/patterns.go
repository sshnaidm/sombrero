package main

// GetAllPatterns returns all regex patterns for sensitive data detection
func GetAllPatterns() map[string]string {
	return map[string]string{
		// Passwords - common password assignments
		"password": `(?i)(password|passwd|pwd|pass)\s*[=:]\s*["']?([^\s"']{3,})["']?`,

		// API Keys - AWS, GitHub, Slack, generic
		"aws_access_key":  `(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
		"github_token":    `(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`,
		"slack_token":     `xox[pboa]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}`,
		"generic_api_key": `(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,})["']?`,

		// Tokens - JWT, OAuth, Bearer
		"jwt_token":    `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`,
		"bearer_token": `(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}`,

		// SSH Private Keys (includes PKCS#8 generic format)
		"ssh_private_key": `-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH) )?PRIVATE KEY-----`,

		// Database connection strings
		"db_connection": `(?i)(?:postgresql|mysql|mongodb|redis|jdbc)://[^\s:]+:[^\s@]+@[^\s/]+`,
		"db_password":   `(?i)(?:db|database)[_-]?(?:password|passwd|pwd)\s*[=:]\s*["']?([^\s"']{3,})["']?`,

		// Internal IP addresses (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
		"internal_ip_10":  `\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`,
		"internal_ip_192": `\b192\.168\.\d{1,3}\.\d{1,3}\b`,
		"internal_ip_172": `\b172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b`,

		// Usernames and emails
		"username": `(?i)(?:user|username|login)\s*[=:]\s*["']?([a-zA-Z0-9_\-\.@]{3,})["']?`,
		"email":    `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`,

		// Secret keys
		"secret_key":  `(?i)(?:secret[_-]?key|secretkey)\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,})["']?`,
		"private_key": `(?i)(?:private[_-]?key|privatekey)\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,})["']?`,

		// Access tokens
		"access_token": `(?i)(?:access[_-]?token|accesstoken)\s*[=:]\s*["']?([A-Za-z0-9_\-\.]{20,})["']?`,

		// High-entropy / unlabeled secrets (optional, can generate false positives)
		"base64_string":      `\b[A-Za-z0-9+/]{40,}={0,2}\b`,
		"hex_string":         `\b[a-fA-F0-9]{32,}\b`,
		"raw_api_key_format": `\b[A-Za-z0-9_\-]{32,}\b`,
	}
}
