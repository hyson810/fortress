package brain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

// EvidenceRecord captures forensic data for a detected threat.
// Records are linked via SHA-256 hash chaining for non-repudiation.
type EvidenceRecord struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	IP            string    `json:"ip"`
	AttackType    string    `json:"attack_type"`
	Score         float64   `json:"score"`
	ResponseLevel string    `json:"response_level"`
	Packets       []string  `json:"packets"`     // packet summaries (truncated)
	Actions       []string  `json:"actions"`     // countermeasures taken
	PrevHash      string    `json:"prev_hash"`
	Hash          string    `json:"hash"`
}

// EvidenceCollector gathers and seals forensic evidence with hash-chain integrity.
type EvidenceCollector struct {
	mu       sync.Mutex
	records  []EvidenceRecord
	lastHash string
	maxSize  int
	exportPath string
}

// NewEvidenceCollector initializes forensic evidence collection.
func NewEvidenceCollector(maxRecords int, exportPath string) *EvidenceCollector {
	return &EvidenceCollector{
		records:    make([]EvidenceRecord, 0, maxRecords),
		maxSize:    maxRecords,
		exportPath: exportPath,
	}
}

// Collect creates a new evidence record, linked to the previous via hash chain.
func (ec *EvidenceCollector) Collect(ip, attackType string, score float64, level ResponseLevel, actions []string) *EvidenceRecord {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	record := EvidenceRecord{
		ID:            fmt.Sprintf("ev-%s-%d", ip, time.Now().UnixNano()),
		Timestamp:     time.Now(),
		IP:            ip,
		AttackType:    attackType,
		Score:         score,
		ResponseLevel: level.String(),
		Actions:       actions,
		PrevHash:      ec.lastHash,
	}

	// Compute hash chain link
	payload := fmt.Sprintf("%s|%s|%s|%s|%.2f|%s|%s",
		record.ID, record.Timestamp.Format(time.RFC3339Nano),
		record.IP, record.AttackType, record.Score,
		record.ResponseLevel, ec.lastHash)
	hash := sha256.Sum256([]byte(payload))
	record.Hash = hex.EncodeToString(hash[:])

	ec.records = append(ec.records, record)
	ec.lastHash = record.Hash

	// Ring buffer behavior
	if len(ec.records) > ec.maxSize {
		ec.records = ec.records[len(ec.records)-ec.maxSize:]
	}

	return &record
}

// VerifyChain checks the integrity of the entire evidence chain.
// Returns true if all hash links are valid.
func (ec *EvidenceCollector) VerifyChain() bool {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	prevHash := ""
	for i, r := range ec.records {
		if i == 0 {
			prevHash = r.Hash
			continue
		}
		if r.PrevHash != prevHash {
			return false
		}
		// Recompute and verify
		payload := fmt.Sprintf("%s|%s|%s|%s|%.2f|%s|%s",
			r.ID, r.Timestamp.Format(time.RFC3339Nano),
			r.IP, r.AttackType, r.Score,
			r.ResponseLevel, r.PrevHash)
		hash := sha256.Sum256([]byte(payload))
		if hex.EncodeToString(hash[:]) != r.Hash {
			return false
		}
		prevHash = r.Hash
	}
	return true
}

// ExportJSON serializes all evidence records to a JSON file.
func (ec *EvidenceCollector) ExportJSON() error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	if ec.exportPath == "" {
		ec.exportPath = "/var/lib/fortress/evidence/chain.json"
	}

	data, err := json.MarshalIndent(ec.records, "", "  ")
	if err != nil {
		return fmt.Errorf("evidence marshal: %w", err)
	}

	if err := os.MkdirAll("/var/lib/fortress/evidence", 0700); err != nil {
		return fmt.Errorf("evidence mkdir: %w", err)
	}

	if err := os.WriteFile(ec.exportPath, data, 0600); err != nil {
		return fmt.Errorf("evidence write: %w", err)
	}

	return nil
}

// Count returns the number of collected evidence records.
func (ec *EvidenceCollector) Count() int {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	return len(ec.records)
}

// LastRecord returns the most recent evidence record.
func (ec *EvidenceCollector) LastRecord() *EvidenceRecord {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	if len(ec.records) == 0 {
		return nil
	}
	r := ec.records[len(ec.records)-1]
	return &r
}

// ChainHead returns the latest hash in the evidence chain.
func (ec *EvidenceCollector) ChainHead() string {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	return ec.lastHash
}

// ForIP returns all evidence records for a specific IP.
func (ec *EvidenceCollector) ForIP(ip string) []EvidenceRecord {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	var result []EvidenceRecord
	for _, r := range ec.records {
		if r.IP == ip {
			result = append(result, r)
		}
	}
	return result
}

// Capture starts a tcpdump packet capture for the given IP and writes to
// the specified file. This implements the V3.1 EvidenceCollector.capture()
// for automatic forensic packet capture.
//
// On Linux, this runs tcpdump with a 10-second capture window.
// On non-Linux platforms, it returns nil (no-op).
func (ec *EvidenceCollector) Capture(ip string, outputPath string) error {
	return capturePacket(ip, outputPath)
}

// Clear removes all records (used after successful export).
func (ec *EvidenceCollector) Clear() {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.records = ec.records[:0]
	ec.lastHash = ""
}

// capturePacket runs tcpdump to capture packets for the given IP.
// On Linux this executes tcpdump; on other platforms it's a no-op.
func capturePacket(ip string, outputPath string) error {
	if runtime.GOOS != "linux" {
		return nil // tcpdump not available on non-Linux
	}

	// Check tcpdump availability.
	if _, err := exec.LookPath("tcpdump"); err != nil {
		return fmt.Errorf("tcpdump not found: %w", err)
	}

	// Capture for 10 seconds, max 1000 packets.
	cmd := exec.Command("tcpdump",
		"-i", "any",
		"-w", outputPath,
		"-c", "1000",
		"-W", "1",
		"-G", "10",
		"host", ip,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("tcpdump start: %w", err)
	}

	// Run in background — don't block evidence collection.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[evidence] tcpdump wait panic: %v\nstack: %s", r, debug.Stack())
			}
		}()
		if err := cmd.Wait(); err != nil {
			// tcpdump returns non-zero on timeout, which is expected.
		}
	}()

	return nil
}
