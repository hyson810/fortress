package brain

import (
	"math"
	"time"
)

// defaultHalfLife is the period over which a threat score halves in the
// absence of new signals.  30 minutes balances responsiveness against
// noise suppression.
const defaultHalfLife = 30 * time.Minute

// DecayScore applies exponential decay to a threat score.
//
// After one half-life the score is halved; after two it is quartered,
// etc.  A zero or negative halfLife falls back to defaultHalfLife.
// When elapsed <= 0 the original score is returned unchanged.
func DecayScore(score float64, lastSeen time.Time, halfLife time.Duration) float64 {
	if halfLife <= 0 {
		halfLife = defaultHalfLife
	}
	elapsed := time.Since(lastSeen)
	if elapsed <= 0 {
		return score
	}
	lambda := math.Ln2 / float64(halfLife)
	return score * math.Exp(-lambda*float64(elapsed))
}
