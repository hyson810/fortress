package dagger_test

import (
	"testing"
)

func TestSharedCryptoRoundtrip(t *testing.T) {
	t.Skip("requires running teamserver with test keys")
}

func TestSessionEnvelopeRoundtrip(t *testing.T) {
	t.Skip("integration test")
}

func TestKeyExchangeCompatibility(t *testing.T) {
	t.Skip("requires Rust + Go side-by-side")
}

func TestBuilderGeneratesBinary(t *testing.T) {
	t.Skip("requires Rust toolchain")
}

func TestHTTPSListenerStarts(t *testing.T) {
	t.Skip("integration test")
}

func TestFullTaskRoundtrip(t *testing.T) {
	t.Skip("integration test")
}
