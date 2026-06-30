package listener

import (
	"log"
	"net"
	"runtime/debug"
	"time"

	"github.com/fortress/v6/dagger/shared"
)

type DNSListener struct {
	addr        string
	conn        *net.UDPConn
	OnData      Callback
	rateLimiter *shared.RateLimiter
}

func NewDNSListener(addr string, cb Callback) *DNSListener {
	return &DNSListener{
		addr:        addr,
		OnData:      cb,
		rateLimiter: shared.NewRateLimiter(5, 10, 5*time.Minute),
	}
}

func (l *DNSListener) Start() error {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[listener/dns] panic: %v\nstack: %s", r, debug.Stack())
		}
	}()
	addr, err := net.ResolveUDPAddr("udp", l.addr)
	if err != nil {
		return err
	}
	l.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	log.Printf("[listener/dns] starting on %s", l.addr)
	buf := make([]byte, 512)
	for {
		n, remote, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		// Rate limit: drop silently if exceeded
		if !l.rateLimiter.Allow(remote.IP.String()) {
			continue
		}
		l.OnData("dns", buf[:n])
		// Respond with echo (production: proper DNS response)
		l.conn.WriteToUDP(buf[:n], remote)
	}
}
