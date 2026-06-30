package audit

import (
    "bufio"
    "context"
    "log"
    "os"
    "regexp"
    "strings"
    "time"
)

type LogRule struct {
    ID          string
    Pattern     *regexp.Regexp
    Severity    int
    Score       float64
    Description string
    Category    string
}

type LogWatcher struct {
    cfg        LogWatcherConfig
    rules      []LogRule
    stopCh     chan struct{}
}

func NewLogWatcher(cfg LogWatcherConfig) *LogWatcher {
    return &LogWatcher{
        cfg:    cfg,
        rules:  defaultRules(),
        stopCh: make(chan struct{}),
    }
}

func (l *LogWatcher) Start(ctx context.Context, alertCh chan<- AuditAlert) {
    for _, path := range l.cfg.LogPaths {
        go l.watchFile(ctx, path, alertCh)
    }
}

func (l *LogWatcher) Stop() { close(l.stopCh) }

func (l *LogWatcher) watchFile(ctx context.Context, path string, alertCh chan<- AuditAlert) {
    f, err := os.Open(path)
    if err != nil {
        log.Printf("[audit] cannot open %s: %v", path, err)
        return
    }
    defer f.Close()
    f.Seek(0, 2)

    reader := bufio.NewReader(f)
    for {
        select {
        case <-ctx.Done(): return
        case <-l.stopCh: return
        default:
        }
        line, err := reader.ReadString('\n')
        if err != nil {
            time.Sleep(500 * time.Millisecond)
            continue
        }
        line = strings.TrimRight(line, "\n\r")
        if line == "" { continue }
        l.checkLine(line, alertCh)
    }
}

func (l *LogWatcher) checkLine(line string, alertCh chan<- AuditAlert) {
    for _, rule := range l.rules {
        if rule.Pattern.MatchString(line) {
            sendAuditAlert(alertCh, AuditAlert{
                Type: "log", Severity: rule.Severity, Score: rule.Score,
                Message: rule.ID + ": " + rule.Description + " — " + truncateStr(line, 120),
                Timestamp: time.Now(),
            })
            return
        }
    }
}

func defaultRules() []LogRule {
    return []LogRule{
        {ID: "L002", Severity: 4, Score: 50, Pattern: regexp.MustCompile(`Failed password for root from`), Description: "SSH root brute force", Category: "auth_fail"},
        {ID: "L001", Severity: 3, Score: 30, Pattern: regexp.MustCompile(`Failed password for.*from`), Description: "SSH password failure", Category: "auth_fail"},
        {ID: "L003", Severity: 2, Score: 10, Pattern: regexp.MustCompile(`Accepted publickey for`), Description: "SSH successful login", Category: "auth_success"},
        {ID: "L004", Severity: 4, Score: 40, Pattern: regexp.MustCompile(`sudo.*COMMAND=.*-u root`), Description: "Sudo privilege escalation", Category: "privilege"},
        {ID: "L005", Severity: 3, Score: 30, Pattern: regexp.MustCompile(`Invalid user.*from`), Description: "SSH invalid user", Category: "auth_fail"},
        {ID: "L006", Severity: 3, Score: 30, Pattern: regexp.MustCompile(`PAM.*authentication failure`), Description: "PAM auth failure", Category: "auth_fail"},
        {ID: "L007", Severity: 3, Score: 25, Pattern: regexp.MustCompile(`pam_unix.*authentication failure`), Description: "Unix auth failure", Category: "auth_fail"},
        {ID: "L008", Severity: 2, Score: 20, Pattern: regexp.MustCompile(`CRON.*\(root\)`), Description: "Cron job as root", Category: "scheduler"},
        {ID: "L009", Severity: 2, Score: 10, Pattern: regexp.MustCompile(`User .* logged in`), Description: "User login", Category: "auth_success"},
        {ID: "L011", Severity: 3, Score: 25, Pattern: regexp.MustCompile(`polkitd.*Authentication failure`), Description: "PolicyKit failure", Category: "auth_fail"},
        {ID: "L012", Severity: 2, Score: 15, Pattern: regexp.MustCompile(`iptables.*DROP`), Description: "Firewall drop", Category: "network"},
        {ID: "L013", Severity: 4, Score: 50, Pattern: regexp.MustCompile(`FAILED su for .* by`), Description: "Failed su", Category: "privilege"},
        {ID: "L014", Severity: 5, Score: 80, Pattern: regexp.MustCompile(`rkhunter.*Warning`), Description: "Rootkit warning", Category: "rootkit"},
        {ID: "L015", Severity: 2, Score: 15, Pattern: regexp.MustCompile(`UFW BLOCK`), Description: "UFW blocked", Category: "network"},
    }
}

func sendAuditAlert(alertCh chan<- AuditAlert, a AuditAlert) {
    select { case alertCh <- a: default: }
}

func truncateStr(s string, n int) string {
    if len(s) <= n { return s }
    return s[:n] + "..."
}
