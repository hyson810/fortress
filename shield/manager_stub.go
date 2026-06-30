//go:build !linux

package shield

// Start is a no-op on non-Linux platforms.
func (m *Manager) Start() {}
