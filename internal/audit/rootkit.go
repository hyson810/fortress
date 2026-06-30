package audit

import "context"

type RootkitScanner struct{}

func NewRootkitScanner(cfg RootkitConfig) *RootkitScanner { return &RootkitScanner{} }
func (r *RootkitScanner) Start(ctx context.Context, alertCh chan<- AuditAlert) {}
func (r *RootkitScanner) Stop() {}
