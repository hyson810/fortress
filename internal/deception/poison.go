package deception

import "log"

// PoisonEngine injects false vulnerability data into attacker
// reconnaissance flows, polluting their intelligence gathering.
type PoisonEngine struct {
	active bool
}

// NewPoisonEngine creates a new PoisonEngine in an inactive state.
func NewPoisonEngine() *PoisonEngine { return &PoisonEngine{} }

// Inject feeds a fake vulnerability entry to the target IP,
// poisoning any scans or enumerations they perform.
func (p *PoisonEngine) Inject(ip, fakeVuln string) {
	p.active = true
	log.Printf("[deception] poison: injecting fake vulnerability %q to %s", fakeVuln, ip)
}
