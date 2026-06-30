package audit

import (
    "testing"
)

func TestLogRuleMatchRootBrute(t *testing.T) {
    rules := defaultRules()
    line := "Jun 30 12:00:00 server sshd[1234]: Failed password for root from 192.168.1.1"
    for _, rule := range rules {
        if rule.Pattern.MatchString(line) {
            if rule.ID != "L002" {
                t.Errorf("expected L002, got %s", rule.ID)
            }
            return
        }
    }
    t.Error("no rule matched")
}

func TestLogRuleNoMatch(t *testing.T) {
    rules := defaultRules()
    line := "Jun 30 12:00:00 server kernel: random: crng init done"
    for _, rule := range rules {
        if rule.Pattern.MatchString(line) {
            t.Errorf("unexpected match: %s", rule.ID)
        }
    }
}

func TestLogRuleSUFailure(t *testing.T) {
    rules := defaultRules()
    line := "Jun 30 12:00:00 server su[1234]: FAILED su for root by user"
    for _, rule := range rules {
        if rule.Pattern.MatchString(line) {
            if rule.ID != "L013" {
                t.Errorf("expected L013, got %s", rule.ID)
            }
            return
        }
    }
    t.Error("no rule matched for su failure")
}

func TestTruncateStr(t *testing.T) {
    if truncateStr("short", 10) != "short" { t.Error("short truncation failed") }
    s := truncateStr("this is a very long string that should be truncated", 20)
    if len(s) != 23 || s[len(s)-3:] != "..." { t.Error("long truncation failed:", s) }
}

func TestDefaultRuleCount(t *testing.T) {
    rules := defaultRules()
    if len(rules) != 14 {
        t.Errorf("expected 14 rules, got %d", len(rules))
    }
}
