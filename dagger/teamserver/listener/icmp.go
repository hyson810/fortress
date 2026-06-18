package listener

import "log"

type ICMPListener struct {
	OnData Callback
}

func NewICMPListener(cb Callback) *ICMPListener {
	return &ICMPListener{OnData: cb}
}

func (l *ICMPListener) Start() error {
	log.Printf("[listener/icmp] raw ICMP listener (requires root/cap_net_raw)")
	return nil
}
