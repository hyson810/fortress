package fusion

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// FfufMatch represents a single successful fuzz match from ffuf output.
type FfufMatch struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Size       int64  `json:"size"`
	Words      int64  `json:"words"`
	Lines      int64  `json:"lines"`
}

// FfufResult summarizes the output of an ffuf fuzzing run.
type FfufResult struct {
	URL      string        `json:"url"`
	Matches  []FfufMatch   `json:"matches"`
	Duration time.Duration `json:"duration"`
}

// Ffuf wraps the ffuf binary for web fuzzing.
type Ffuf struct {
	binPath  string
	wordlist string
	timeout  time.Duration
}

// NewFfuf creates a new Ffuf using the supplied binary and wordlist paths.
func NewFfuf(binPath, wordlist string) *Ffuf {
	return &Ffuf{binPath: binPath, wordlist: wordlist, timeout: 15 * time.Minute}
}

// Fuzz runs ffuf against url with the configured wordlist using the FUZZ
// keyword. The url must contain the string "FUZZ" as a placeholder, e.g.
// "http://target.com/FUZZ".
func (f *Ffuf) Fuzz(url, wordlist string) (*FfufResult, error) {
	if err := validateFfufURL(url); err != nil {
		return nil, fmt.Errorf("ffuf: %w", err)
	}

	// Validate wordlist parameter to prevent injection.
	if wordlist == "" {
		return nil, fmt.Errorf("ffuf: wordlist must not be empty")
	}
	if strings.HasPrefix(wordlist, "-") {
		return nil, fmt.Errorf("ffuf: wordlist %q must not start with '-'", wordlist)
	}
	if strings.ContainsAny(wordlist, ";|&`$(){}<>\n\r\\") {
		return nil, fmt.Errorf("ffuf: wordlist %q contains forbidden characters", wordlist)
	}

	if !strings.Contains(url, "FUZZ") {
		return nil, fmt.Errorf("ffuf: URL must contain FUZZ placeholder, got %q", url)
	}

	start := time.Now()
	cmd := exec.Command(f.binPath,
		"-u", url,
		"-w", wordlist,
		"-json",
		"-mc", "200,204,301,302,307,401,403,405,500",
	)
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("ffuf fuzz %s: %w: %s", url, err, string(out))
	}

	result := ParseFfufJSON(strings.NewReader(string(out)))
	result.URL = url
	result.Duration = elapsed

	return result, nil
}

// ParseFfufJSON parses ffuf's newline-delimited JSON output into
// structured FfufMatch entries. Malformed lines are skipped and logged.
func ParseFfufJSON(reader jsonReader) *FfufResult {
	result := &FfufResult{}

	dec := json.NewDecoder(reader)
	for {
		var raw struct {
			Input      map[string]string `json:"input"`
			URL        string            `json:"url"`
			StatusCode int               `json:"status_code"`
			Length     int64             `json:"length"`
			Words      int64             `json:"words"`
			Lines      int64             `json:"lines"`
		}
		if err := dec.Decode(&raw); err != nil {
			break
		}

		path := raw.URL
		if path == "" {
			// Reconstruct from input.
			if v, ok := raw.Input["FUZZ"]; ok {
				path = v
			} else {
				continue
			}
		}

		result.Matches = append(result.Matches, FfufMatch{
			Path:       path,
			StatusCode: raw.StatusCode,
			Size:       raw.Length,
			Words:      raw.Words,
			Lines:      raw.Lines,
		})
	}

	return result
}

// validateFfufURL checks that a URL is safe to pass to ffuf and
// contains no shell metacharacters or flag injection patterns.
func validateFfufURL(url string) error {
	if url == "" {
		return fmt.Errorf("fusion: URL must not be empty")
	}

	if strings.HasPrefix(url, "-") {
		return fmt.Errorf("fusion: URL %q must not start with '-'", url)
	}

	if strings.ContainsAny(url, ";|&`$(){}<>\n\r\\") {
		return fmt.Errorf("fusion: URL %q contains forbidden characters", url)
	}

	return nil
}
