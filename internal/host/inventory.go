package host

import "context"

// InventoryCollector handles system inventory collection.
type InventoryCollector struct {
	cfg InventoryConfig
}

// NewInventoryCollector creates a new InventoryCollector.
func NewInventoryCollector(cfg InventoryConfig) *InventoryCollector {
	return &InventoryCollector{cfg: cfg}
}

// Start begins periodic inventory collection.
func (ic *InventoryCollector) Start(ctx context.Context) {
	// TODO: implement in WZ Task 2
	_ = ctx
}

// Stop gracefully shuts down the inventory collector.
func (ic *InventoryCollector) Stop() {
	// TODO: implement in WZ Task 2
}
