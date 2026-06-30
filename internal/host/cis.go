package host

import "context"

// CISChecker handles CIS benchmark compliance checking.
type CISChecker struct {
	cfg CISConfig
}

// NewCISChecker creates a new CISChecker.
func NewCISChecker(cfg CISConfig) *CISChecker {
	return &CISChecker{cfg: cfg}
}

// Start begins the CIS compliance checking loop. It sends alerts to the provided channel.
func (c *CISChecker) Start(ctx context.Context, alertCh chan<- HostAlert) {
	// TODO: implement in WZ Task 5
	_ = ctx
	_ = alertCh
}

// Stop gracefully shuts down the CIS checker.
func (c *CISChecker) Stop() {
	// TODO: implement in WZ Task 5
}
