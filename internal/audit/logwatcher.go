package audit

import "context"

type LogWatcher struct{}

func NewLogWatcher(cfg LogWatcherConfig) *LogWatcher { return &LogWatcher{} }
func (l *LogWatcher) Start(ctx context.Context, alertCh chan<- AuditAlert) {}
func (l *LogWatcher) Stop() {}
