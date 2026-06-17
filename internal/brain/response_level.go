package brain

// ResponseLevel maps to the 4-tier response ladder for autonomous defense.
type ResponseLevel int

const (
	ResponseA ResponseLevel = iota // Silent observation — log only
	ResponseB                       // Active recon — WHOIS, rate limit, abuse report
	ResponseC                       // Predator mode — tarpit, honeypot, ban, OSINT, attack scan
	ResponseD                       // Black hole — full counterstrike
)

// String returns a human-readable label for the response level.
func (l ResponseLevel) String() string {
	switch l {
	case ResponseA:
		return "A·静默"
	case ResponseB:
		return "B·侦查"
	case ResponseC:
		return "C·掠食者"
	case ResponseD:
		return "D·黑洞"
	default:
		return "unknown"
	}
}
