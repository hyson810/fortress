package host

import "context"

// FIMMonitor handles file integrity monitoring.
type FIMMonitor struct {
	cfg FIMConfig
}

// NewFIMMonitor creates a new FIMMonitor.
func NewFIMMonitor(cfg FIMConfig) *FIMMonitor {
	return &FIMMonitor{cfg: cfg}
}

// Start begins the FIM monitoring loop. It sends alerts to the provided channel.
func (f *FIMMonitor) Start(ctx context.Context, alertCh chan<- HostAlert) {
	// TODO: implement in WZ Task 3
	_ = ctx
	_ = alertCh
}

// Stop gracefully shuts down the FIM monitor.
func (f *FIMMonitor) Stop() {
	// TODO: implement in WZ Task 3
}
