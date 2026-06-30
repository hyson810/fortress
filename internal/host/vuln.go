package host

import "context"

// VulnScanner handles vulnerability scanning.
type VulnScanner struct {
	cfg VulnConfig
}

// NewVulnScanner creates a new VulnScanner.
func NewVulnScanner(cfg VulnConfig) *VulnScanner {
	return &VulnScanner{cfg: cfg}
}

// Start begins the vulnerability scanning loop. It sends alerts to the provided channel.
func (v *VulnScanner) Start(ctx context.Context, alertCh chan<- HostAlert) {
	// TODO: implement in WZ Task 4
	_ = ctx
	_ = alertCh
}

// Stop gracefully shuts down the vulnerability scanner.
func (v *VulnScanner) Stop() {
	// TODO: implement in WZ Task 4
}
