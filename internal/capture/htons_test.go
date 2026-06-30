package capture

import "testing"

func TestHtons(t *testing.T) {
	tests := []struct {
		input    uint16
		expected uint16
	}{
		{0x0000, 0x0000},
		{0x0100, 0x0001},
		{0x0001, 0x0100},
		{0x1234, 0x3412},
		{0xffff, 0xffff},
		{0x0080, 0x8000},
		{0x0800, 0x0008},
		{0xabcd, 0xcdab},
		{0x00ff, 0xff00},
	}

	for _, tt := range tests {
		result := htons(tt.input)
		if result != tt.expected {
			t.Errorf("htons(0x%04x) = 0x%04x, want 0x%04x", tt.input, result, tt.expected)
		}
	}
}
