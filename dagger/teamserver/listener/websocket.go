package listener

import (
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/fortress/v6/dagger/shared"
	"github.com/gorilla/websocket"
)

// DefaultWSPreSharedToken is the default token expected in the
// X-Auth-Token header or ?token= query parameter for WebSocket connections.
// In production, override this with a strong random value.
var DefaultWSPreSharedToken = "CHANGE_ME_IN_PRODUCTION"

type WSListener struct {
	addr        string
	OnData      Callback
	upgrader    websocket.Upgrader
	rateLimiter *shared.RateLimiter
}

func NewWSListener(addr string, cb Callback) *WSListener {
	l := &WSListener{
		addr:        addr,
		OnData:      cb,
		rateLimiter: shared.NewRateLimiter(5, 5, 5*time.Minute),
	}
	l.upgrader = websocket.Upgrader{
		CheckOrigin: l.checkOrigin,
	}
	return l
}

// checkOrigin validates WebSocket upgrade requests.
// It requires either the X-Auth-Token header or ?token= query parameter
// to match the pre-shared token. This replaces the previous permissive
// "return true" policy that allowed cross-origin connections from anywhere.
func (l *WSListener) checkOrigin(r *http.Request) bool {
	token := r.Header.Get("X-Auth-Token")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	return token != "" && token == DefaultWSPreSharedToken
}

func (l *WSListener) Start() error {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[listener/ws] panic: %v\nstack: %s", r, debug.Stack())
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", l.handleWS)
	log.Printf("[listener/ws] starting on %s", l.addr)
	return http.ListenAndServe(l.addr, mux)
}

func (l *WSListener) handleWS(w http.ResponseWriter, r *http.Request) {
	// Rate limit WebSocket upgrade attempts
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	if !l.rateLimiter.Allow(clientIP) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	conn, err := l.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return
	}
	resp, err := l.OnData("ws", msg)
	if err != nil {
		return
	}
	conn.WriteMessage(websocket.BinaryMessage, resp)
}
