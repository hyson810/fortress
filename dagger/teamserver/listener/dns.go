package listener

import (
	"log"
	"net"
)

type DNSListener struct {
	addr   string
	conn   *net.UDPConn
	OnData Callback
}

func NewDNSListener(addr string, cb Callback) *DNSListener {
	return &DNSListener{addr: addr, OnData: cb}
}

func (l *DNSListener) Start() error {
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
		l.OnData("dns", buf[:n])
		// Respond with echo (production: proper DNS response)
		l.conn.WriteToUDP(buf[:n], remote)
	}
}
