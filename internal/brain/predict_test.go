package brain

import (
	"testing"
)

func TestPredictiveEngine_CodeAnalysis(t *testing.T) {
	pe := NewPredictiveEngine()

	// Vulnerable PHP code
	code := `<?php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $id;
$result = mysql_query($query);
echo "<div>Hello " . $_GET['name'] . "</div>";
$file = fopen("/var/www/uploads/" . $_GET['file'], "r");
$cmd = system("ping -c 1 " . $_GET['ip']);
?>`

	predictions := pe.AnalyzeFile("test.php", []byte(code), "php")
	t.Logf("PHP analysis: %d predictions", len(predictions))
	for _, p := range predictions {
		t.Logf("  %s: %s (risk=%.1f, line=%d)", p.CWE, p.Title, p.RiskScore, p.Line)
	}
	if len(predictions) < 3 {
		t.Errorf("expected >=3 predictions for vulnerable PHP code, got %d", len(predictions))
	}
}

func TestPredictiveEngine_BannerAnalysis(t *testing.T) {
	pe := NewPredictiveEngine()
	predictions := pe.AnalyzeService("10.0.0.1", "Apache/2.2.15 (Unix) PHP/5.3.3", "http")
	t.Logf("Banner analysis: %d predictions", len(predictions))
	for _, p := range predictions {
		t.Logf("  %s: %s (risk=%.1f)", p.CWE, p.Title, p.RiskScore)
	}
	if len(predictions) == 0 {
		t.Error("expected predictions for Apache 2.2 + PHP 5.3")
	}
}

func TestPredictiveEngine_HighRiskFilter(t *testing.T) {
	pe := NewPredictiveEngine()
	pe.AnalyzeFile("test.go", []byte(`password = "admin123"`), "go")
	highRisk := pe.GetHighRiskPredictions(70)
	t.Logf("High risk predictions (>=70): %d", len(highRisk))
}
