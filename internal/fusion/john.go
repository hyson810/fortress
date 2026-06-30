package fusion

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CrackedEntry represents a single successfully cracked password hash
// along with metadata about the hash type.
type CrackedEntry struct {
	Hash     string `json:"hash"`
	Password string `json:"password"`
	HashType string `json:"hash_type"`
}

// JohnResult aggregates the output of a John the Ripper cracking run.
type JohnResult struct {
	CrackedHashes []CrackedEntry `json:"cracked_hashes"`
	Duration      time.Duration  `json:"duration"`
}

// JohnRipper wraps the john binary for offline password hash cracking.
type JohnRipper struct {
	binPath  string
	wordlist string
}

// NewJohn creates a new JohnRipper using the supplied binary path and
// wordlist path. If wordlist is empty, john will use its default
// wordlist or incremental mode (configured per invocation).
func NewJohn(binPath, wordlist string) *JohnRipper {
	return &JohnRipper{binPath: binPath, wordlist: wordlist}
}

// Crack runs john against a hash file using the configured wordlist.
// The hash file should contain one or more hashes in a format recognized
// by john (e.g., /etc/shadow, pwdump, raw hashes).
func (j *JohnRipper) Crack(hashFile string) (*JohnResult, error) {
	if hashFile == "" {
		return nil, fmt.Errorf("john: hash file must not be empty")
	}

	if _, err := os.Stat(hashFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("john: hash file not found: %s", hashFile)
	}

	start := time.Now()

	args := []string{"--wordlist=" + j.wordlist, hashFile}
	if j.wordlist == "" {
		args = []string{hashFile} // default mode
	}

	cmd := exec.Command(j.binPath, args...)
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("john crack %s: %w: %s", hashFile, err, string(out))
	}

	cracked := ParseJohnOutput(string(out))

	// Also read from john --show to get cracked passwords.
	showCmd := exec.Command(j.binPath, "--show", hashFile)
	showOut, _ := showCmd.CombinedOutput()
	showCracked := ParseJohnOutput(string(showOut))

	// Merge results, preferring --show output for completeness.
	if len(showCracked) > 0 {
		cracked = showCracked
	}

	return &JohnResult{
		CrackedHashes: cracked,
		Duration:      elapsed,
	}, nil
}

// CrackSingle cracks a single hash string by writing it to a temporary
// file and invoking john. hashType is passed as --format if non-empty.
func (j *JohnRipper) CrackSingle(hash string, hashType string) (*JohnResult, error) {
	if hash == "" {
		return nil, fmt.Errorf("john: hash must not be empty")
	}

	// Reject shell metacharacters in the hash string.
	if strings.ContainsAny(hash, ";|&`$(){}<>\n\r\\") {
		return nil, fmt.Errorf("john: hash contains forbidden characters")
	}

	// Write hash to a temp file.
	f, err := os.CreateTemp("", "fortress-john-*.hash")
	if err != nil {
		return nil, fmt.Errorf("john: create temp file: %w", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(hash + "\n"); err != nil {
		f.Close()
		return nil, fmt.Errorf("john: write temp file: %w", err)
	}
	f.Close()

	start := time.Now()

	args := []string{"--wordlist=" + j.wordlist}
	if hashType != "" {
		args = append(args, "--format="+hashType)
	}
	args = append(args, f.Name())

	cmd := exec.Command(j.binPath, args...)
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	if err != nil {
		// Non-fatal: john may exit non-zero even when some hashes cracked.
		// We still try to parse the output.
	}

	cracked := ParseJohnOutput(string(out))

	// Also try --show.
	showCmd := exec.Command(j.binPath, "--show", f.Name())
	showOut, _ := showCmd.CombinedOutput()
	showCracked := ParseJohnOutput(string(showOut))
	if len(showCracked) > 0 {
		cracked = showCracked
	}

	return &JohnResult{
		CrackedHashes: cracked,
		Duration:      elapsed,
	}, nil
}

// ParseJohnOutput parses john stdout (from a cracking session or --show)
// into structured CrackedEntry values. Lines that do not match the
// expected format are silently skipped.
func ParseJohnOutput(output string) []CrackedEntry {
	var entries []CrackedEntry

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Skip informational lines.
		if strings.HasPrefix(line, "Warning:") ||
			strings.HasPrefix(line, "Loaded") ||
			strings.HasPrefix(line, "Proceeding") ||
			strings.HasPrefix(line, "Using") ||
			strings.HasPrefix(line, "Will run") ||
			strings.HasPrefix(line, "Press") ||
			strings.HasPrefix(line, "0g") ||
			strings.HasPrefix(line, "Session") ||
			strings.Contains(line, "password hashes cracked") {
			continue
		}

		// Output format for --show: user:password
		// Output format during cracking: hash:password
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 && parts[1] != "" {
			entries = append(entries, CrackedEntry{
				Hash:     parts[0],
				Password: parts[1],
			})
			continue
		}

		// Try to match "password123 (user)" format.
		if idx := strings.Index(line, " ("); idx > 0 && strings.HasSuffix(line, ")") {
			password := line[:idx]
			hash := line[idx+2 : len(line)-1]
			entries = append(entries, CrackedEntry{
				Hash:     hash,
				Password: password,
			})
		}
	}

	return entries
}

// SupportedFormats returns a list of commonly requested hash formats that
// john supports. This is a curated subset — john supports hundreds of
// formats, and the full list can be obtained via "john --list=formats".
func SupportedFormats() []string {
	return []string{
		"raw-md5",
		"raw-sha1",
		"raw-sha256",
		"raw-sha512",
		"nt",
		"ntlm",
		"ntlmv2",
		"lm",
		"mysql",
		"postgres",
		"oracle",
		"krb5tgs",
		"krb5asrep",
		"ssh",
		"zip",
		"rar",
		"7z",
		"pdf",
		"office",
		"ethereum",
		"bitcoin",
	}
}
