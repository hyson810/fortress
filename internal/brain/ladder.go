package brain

// ladderTier defines a single rung on the response escalation ladder.
type ladderTier struct {
	MaxScore float64
	Level    ResponseLevel
	Name     string
	Desc     string
}

// defaultLadder is the conservative tier mapping for normal deployments.
var defaultLadder = []ladderTier{
	{25, ResponseA, "A·静默", "Silent observation — log only"},
	{50, ResponseB, "B·侦查", "Active recon — WHOIS, rate limit, abuse report draft"},
	{75, ResponseC, "C·掠食者", "Predator — tarpit, honeypot, ban, OSINT, attack scan"},
	{100, ResponseD, "D·黑洞", "Black hole — LLM deception, full weapon chain, swarm immunity"},
}

// aggressiveLadder lowers thresholds so the defender escalates faster.
var aggressiveLadder = []ladderTier{
	{15, ResponseA, "A·静默", "Silent observation"},
	{30, ResponseB, "B·侦查", "Active recon"},
	{55, ResponseC, "C·掠食者", "Predator"},
	{100, ResponseD, "D·黑洞", "Black hole"},
}

// DetermineResponse maps a numeric score to the appropriate response
// tier, name, and description.
func DetermineResponse(score float64, aggressive bool) (ResponseLevel, string, string) {
	ladder := defaultLadder
	if aggressive {
		ladder = aggressiveLadder
	}
	for _, tier := range ladder {
		if score <= tier.MaxScore {
			return tier.Level, tier.Name, tier.Desc
		}
	}
	return ResponseD, "D·黑洞", "Black hole"
}

// UpdateResponseLevel sets the ResponseLevel field on an IPRecord
// based on its current TotalScore and the ladder selection.
func UpdateResponseLevel(r *IPRecord, aggressive bool) {
	r.ResponseLevel, _, _ = DetermineResponse(r.TotalScore, aggressive)
}
