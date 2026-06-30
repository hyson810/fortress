package defense

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// BanSource indicates the origin of a ban entry.
type BanSource string

const (
	ManualBlock    BanSource = "manual"
	AutoBlock      BanSource = "auto"
	SwarmConsensus BanSource = "swarm_consensus"
	IntelFeed      BanSource = "threat_intel"
	C2Block        BanSource = "c2"
)

// BanEntry represents a single banned IP with metadata.
type BanEntry struct {
	IP        string    `json:"ip"`
	Source    BanSource `json:"source"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
	ExpiresAt time.Time `json:"expires_at"` // zero = permanent
}

// IsExpired returns true if the ban entry has a finite expiry and has passed.
func (be BanEntry) IsExpired() bool {
	return !be.ExpiresAt.IsZero() && time.Now().After(be.ExpiresAt)
}

// IsPermanent returns true if the ban entry never expires.
func (be BanEntry) IsPermanent() bool {
	return be.ExpiresAt.IsZero()
}

// BanList maintains a multi-source IP ban list with automatic expiry
// and optional JSON persistence.
type BanList struct {
	mu       sync.RWMutex
	entries  map[string]BanEntry
	stopCh   chan struct{}
	persist  bool
	filePath string
}

// NewBanList creates a new empty BanList.
func NewBanList() *BanList {
	bl := &BanList{
		entries: make(map[string]BanEntry),
		stopCh:  make(chan struct{}),
	}
	go bl.autoExpire()
	return bl
}

// EnablePersistence configures automatic JSON-file persistence. The file is
// atomically written on every Add or Remove call.
func (bl *BanList) EnablePersistence(path string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	bl.persist = true
	bl.filePath = path
}

// Add inserts a ban entry. If an entry for the IP already exists, the newer
// timestamp wins for updates.
func (bl *BanList) Add(entry BanEntry) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	if existing, ok := bl.entries[entry.IP]; ok {
		// Keep the newer entry unless the new source is higher priority.
		if entry.Timestamp.Before(existing.Timestamp) &&
			sourcePriority(existing.Source) >= sourcePriority(entry.Source) {
			return
		}
	}

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	bl.entries[entry.IP] = entry
	log.Printf("[banlist] added %s (source=%s reason=%s)", entry.IP, entry.Source, entry.Reason)

	if bl.persist {
		bl.writeLocked()
	}
}

// Remove deletes a ban entry by IP address. Returns true if an entry existed.
func (bl *BanList) Remove(ip string) bool {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	_, ok := bl.entries[ip]
	if ok {
		delete(bl.entries, ip)
		log.Printf("[banlist] removed %s", ip)
		if bl.persist {
			bl.writeLocked()
		}
	}
	return ok
}

// Contains checks whether an IP is currently banned.
func (bl *BanList) Contains(ip string) bool {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	entry, ok := bl.entries[ip]
	if !ok {
		return false
	}
	if entry.IsExpired() {
		return false
	}
	return true
}

// List returns a snapshot of all non-expired ban entries, sorted by timestamp
// (newest first).
func (bl *BanList) List() []BanEntry {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	now := time.Now()
	out := make([]BanEntry, 0, len(bl.entries))
	for _, e := range bl.entries {
		if e.IsExpired() {
			continue
		}
		// Defensive copy for time comparison in snapshot
		if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
			continue
		}
		out = append(out, e)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Timestamp.After(out[j].Timestamp)
	})
	return out
}

// Count returns the number of active (non-expired) ban entries.
func (bl *BanList) Count() int {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	now := time.Now()
	n := 0
	for _, e := range bl.entries {
		if e.ExpiresAt.IsZero() || now.Before(e.ExpiresAt) {
			n++
		}
	}
	return n
}

// CountBySource returns the active count for a specific ban source.
func (bl *BanList) CountBySource(source BanSource) int {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	now := time.Now()
	n := 0
	for _, e := range bl.entries {
		if e.Source != source {
			continue
		}
		if e.ExpiresAt.IsZero() || now.Before(e.ExpiresAt) {
			n++
		}
	}
	return n
}

// MergeFromPeers merges ban entries from swarm peers. When two entries
// conflict (same IP), the newer timestamp wins.
func (bl *BanList) MergeFromPeers(entries []BanEntry) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	added := 0
	for _, e := range entries {
		if existing, ok := bl.entries[e.IP]; ok {
			// Newer timestamp wins for conflicts.
			if !e.Timestamp.After(existing.Timestamp) {
				continue
			}
		}
		if e.Timestamp.IsZero() {
			e.Timestamp = time.Now()
		}
		bl.entries[e.IP] = e
		added++
	}

	log.Printf("[banlist] merged %d entries from peers (%d new)", len(entries), added)

	if bl.persist && added > 0 {
		bl.writeLocked()
	}
}

// AutoExpire starts a background goroutine that periodically removes expired
// entries. Call NewBanList to start this automatically.
//
// Deprecated: auto-expiry is started automatically by NewBanList. This
// method is retained for backwards compatibility.
func (bl *BanList) AutoExpire() {
	// Already started in NewBanList; no-op for callers calling explicitly.
}

// autoExpire is the internal goroutine that removes expired entries.
func (bl *BanList) autoExpire() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bl.ExpireNow()
		case <-bl.stopCh:
			return
		}
	}
}

// ExpireNow immediately removes all expired entries and returns the count.
func (bl *BanList) ExpireNow() int {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	now := time.Now()
	removed := 0
	for ip, e := range bl.entries {
		if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
			delete(bl.entries, ip)
			removed++
		}
	}

	if removed > 0 {
		log.Printf("[banlist] auto-expired %d entries", removed)
		if bl.persist {
			bl.writeLocked()
		}
	}
	return removed
}

// ExportForEBPF returns a slice of IP strings formatted for insertion into
// a BPF map (IPv4 only).
func (bl *BanList) ExportForEBPF() []string {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	now := time.Now()
	ips := make([]string, 0, len(bl.entries))
	for _, e := range bl.entries {
		if e.IsExpired() {
			continue
		}
		if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
			continue
		}
		// BPF maps typically work with IPv4; include both v4 and v6.
		ips = append(ips, e.IP)
	}
	return ips
}

// ExportForNftables returns the ban list formatted for nftables set elements.
func (bl *BanList) ExportForNftables() []string {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	now := time.Now()
	elements := make([]string, 0, len(bl.entries))
	for _, e := range bl.entries {
		if e.IsExpired() {
			continue
		}
		if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
			continue
		}
		if e.IsPermanent() {
			elements = append(elements, e.IP)
		} else {
			remaining := time.Until(e.ExpiresAt)
			elements = append(elements, fmt.Sprintf("%s timeout %ds", e.IP, int(remaining.Seconds())))
		}
	}
	return elements
}

// ImportFromFile reads a list of IP addresses (one per line) and adds them
// as ManualBlock entries.
func (bl *BanList) ImportFromFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("banlist: import %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var ips []string
	for scanner.Scan() {
		line := scanner.Text()
		// Trim comments and whitespace.
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if net.ParseIP(line) != nil {
			ips = append(ips, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("banlist: read %s: %w", path, err)
	}

	bl.mu.Lock()
	now := time.Now()
	for _, ip := range ips {
		bl.entries[ip] = BanEntry{
			IP: ip, Source: ManualBlock, Reason: "imported from " + path,
			Timestamp: now,
		}
	}
	if bl.persist {
		bl.writeLocked()
	}
	bl.mu.Unlock()

	log.Printf("[banlist] imported %d IPs from %s", len(ips), path)
	return len(ips), nil
}

// ExportToFile writes the current ban list as a JSON file.
func (bl *BanList) ExportToFile(path string) error {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	entries := make([]BanEntry, 0, len(bl.entries))
	for _, e := range bl.entries {
		entries = append(entries, e)
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("banlist: marshal: %w", err)
	}
	if err := atomicWriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("banlist: write: %w", err)
	}
	return nil
}

// writeLocked persists the ban list to the configured file path atomically.
// Must be called with bl.mu held.
func (bl *BanList) writeLocked() {
	if bl.filePath == "" {
		return
	}
	entries := make([]BanEntry, 0, len(bl.entries))
	for _, e := range bl.entries {
		entries = append(entries, e)
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		log.Printf("[banlist] marshal: %v", err)
		return
	}
	if err := atomicWriteFile(bl.filePath, data, 0644); err != nil {
		log.Printf("[banlist] write: %v", err)
	}
}

// Stop halts the auto-expiry goroutine. The BanList should not be used after
// calling Stop.
func (bl *BanList) Stop() {
	close(bl.stopCh)
}

// sourcePriority assigns a numeric priority to ban sources for conflict
// resolution. Higher numbers win.
func sourcePriority(s BanSource) int {
	switch s {
	case C2Block:
		return 5
	case SwarmConsensus:
		return 4
	case IntelFeed:
		return 3
	case AutoBlock:
		return 2
	case ManualBlock:
		return 1
	default:
		return 0
	}
}

// atomicWriteFile writes data to a temporary file and renames it to the
// target path for atomic replacement on POSIX systems.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".banlist-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	if err := os.Chmod(tmpPath, perm); err != nil {
		os.Remove(tmpPath)
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}
