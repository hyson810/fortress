package fusion

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// FoundEntry describes a single URL path or DNS subdomain discovered by
// GoBuster during a scan.
type FoundEntry struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Size       int64  `json:"size"`
}

// GoBusterResult summarizes the output of a GoBuster run.
type GoBusterResult struct {
	URL        string        `json:"url"`
	FoundPaths []FoundEntry  `json:"found_paths"`
	Duration   time.Duration `json:"duration"`
}

// GoBuster wraps the gobuster binary for directory and DNS brute forcing.
type GoBuster struct {
	binPath  string
	wordlist string
	timeout  time.Duration
}

// NewGoBuster creates a new GoBuster using the supplied binary path and
// wordlist path. The wordlist is required and must reference an existing
// file; an empty string disables wordlist validation at construction time
// (the binary will report a missing wordlist at scan time).
func NewGoBuster(binPath, wordlist string) *GoBuster {
	return &GoBuster{binPath: binPath, wordlist: wordlist, timeout: 10 * time.Minute}
}

// DirScan runs gobuster in directory/file enumeration mode against url
// using the configured wordlist.
func (g *GoBuster) DirScan(url string) (*GoBusterResult, error) {
	if err := validateURL(url); err != nil {
		return nil, fmt.Errorf("gobuster: %w", err)
	}

	start := time.Now()
	cmd := exec.Command(g.binPath, "dir",
		"-u", url,
		"-w", g.wordlist,
		"-q",
	)
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("gobuster dir scan %s: %w: %s", url, err, string(out))
	}

	result := ParseGoBusterOutput(string(out))
	result.URL = url
	result.Duration = elapsed

	return result, nil
}

// DnsScan runs gobuster in DNS subdomain enumeration mode against domain
// using the configured wordlist.
func (g *GoBuster) DnsScan(domain string) (*GoBusterResult, error) {
	if err := ValidateDomain(domain); err != nil {
		return nil, fmt.Errorf("gobuster: %w", err)
	}

	start := time.Now()
	cmd := exec.Command(g.binPath, "dns",
		"-d", domain,
		"-w", g.wordlist,
		"-q",
	)
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("gobuster dns scan %s: %w: %s", domain, err, string(out))
	}

	result := ParseGoBusterOutput(string(out))
	result.URL = domain
	result.Duration = elapsed

	return result, nil
}

// gobusterLineRE matches gobuster's default output lines. Typical format:
//
//	/path (Status: 200) [Size: 1234]
var gobusterLineRE = regexp.MustCompile(
	`^(\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]`)

// ParseGoBusterOutput parses the stdout output of a gobuster run into
// structured entries. Lines that do not match the expected format are
// silently skipped.
func ParseGoBusterOutput(output string) *GoBusterResult {
	result := &GoBusterResult{}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		matches := gobusterLineRE.FindStringSubmatch(line)
		if len(matches) != 4 {
			log.Printf("[gobuster] unparseable line: %s", line)
			continue
		}

		statusCode, err := strconv.Atoi(matches[2])
		if err != nil {
			statusCode = 0
		}

		size, err := strconv.ParseInt(matches[3], 10, 64)
		if err != nil {
			size = 0
		}

		result.FoundPaths = append(result.FoundPaths, FoundEntry{
			Path:       matches[1],
			StatusCode: statusCode,
			Size:       size,
		})
	}

	return result
}

// validateURL checks that a URL is safe to pass to GoBuster and contains
// no shell metacharacters or flag injection patterns.
func validateURL(url string) error {
	if url == "" {
		return fmt.Errorf("fusion: URL must not be empty")
	}

	if strings.HasPrefix(url, "-") {
		return fmt.Errorf("fusion: URL %q must not start with '-'", url)
	}

	if strings.ContainsAny(url, ";|&`$(){}<>\n\r\\") {
		return fmt.Errorf("fusion: URL %q contains forbidden characters", url)
	}

	// Must have a scheme-like prefix to distinguish from raw domains.
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("fusion: URL %q must start with http:// or https://", url)
	}

	return nil
}
