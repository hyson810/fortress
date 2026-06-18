package websocket

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
)

const (
	BinaryMessage = 2
)

type Upgrader struct {
	CheckOrigin func(r *http.Request) bool
}

func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header) (*Conn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!headerContains(r.Header, "Connection", "upgrade") {
		http.Error(w, "not a websocket request", 400)
		return nil, errors.New("not a websocket request")
	}
	if u.CheckOrigin != nil && !u.CheckOrigin(r) {
		http.Error(w, "origin not allowed", 403)
		return nil, errors.New("origin not allowed")
	}
	h, _ := r.Header["Sec-WebSocket-Key"]
	if len(h) == 0 {
		http.Error(w, "missing key", 400)
		return nil, errors.New("missing sec-websocket-key")
	}
	key := h[0]
	magic := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	hsh := sha1.Sum([]byte(key + magic))
	accept := base64.StdEncoding.EncodeToString(hsh[:])

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("hijacking not supported")
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
	brw.WriteString(resp)
	brw.Flush()

	return newConn(conn, brw), nil
}

func headerContains(h http.Header, key, val string) bool {
	for _, v := range h[http.CanonicalHeaderKey(key)] {
		for _, s := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(s), val) {
				return true
			}
		}
	}
	return false
}

type Conn struct {
	conn net.Conn
	br   *bufio.Reader
}

func newConn(c net.Conn, brw *bufio.ReadWriter) *Conn {
	return &Conn{conn: c, br: brw.Reader}
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

func (c *Conn) ReadMessage() (messageType int, data []byte, err error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c.br, head); err != nil {
		return 0, nil, err
	}

	opcode := head[0] & 0x0F
	masked := head[1]&0x80 != 0
	length := int64(head[1] & 0x7F)

	switch {
	case length == 126:
		b := make([]byte, 2)
		io.ReadFull(c.br, b)
		length = int64(binary.BigEndian.Uint16(b))
	case length == 127:
		b := make([]byte, 8)
		io.ReadFull(c.br, b)
		length = int64(binary.BigEndian.Uint64(b))
	}

	var maskKey [4]byte
	if masked {
		io.ReadFull(c.br, maskKey[:])
	}

	data = make([]byte, length)
	io.ReadFull(c.br, data)

	if masked {
		for i := range data {
			data[i] ^= maskKey[i%4]
		}
	}

	return int(opcode), data, nil
}

func (c *Conn) WriteMessage(messageType int, data []byte) error {
	buf := make([]byte, 0, len(data)+10)
	buf = append(buf, byte(0x80|messageType))

	l := len(data)
	switch {
	case l <= 125:
		buf = append(buf, byte(l))
	case l <= 65535:
		buf = append(buf, 126, byte(l>>8), byte(l))
	default:
		buf = append(buf, 127)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(l))
		buf = append(buf, b...)
	}
	buf = append(buf, data...)

	_, err := c.conn.Write(buf)
	return err
}
