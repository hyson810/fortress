package operator

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/fortress/v6/dagger/shared"
)

type API struct {
	addr        string
	apiKey      string // empty means auth disabled
	onList      func() []string
	onTask      func(sessionID string, taskType uint8, data []byte, timeout int) (interface{}, error)
	rateLimiter *shared.RateLimiter
}

func NewAPI(addr string, apiKey string, onList func() []string, onTask func(string, uint8, []byte, int) (interface{}, error)) *API {
	return &API{
		addr:        addr,
		apiKey:      apiKey,
		onList:      onList,
		onTask:      onTask,
		rateLimiter: shared.NewRateLimiter(50, 100, 5*time.Minute),
	}
}

func (api *API) Start() error {
	mux := http.NewServeMux()
	// Apply middleware: rate limit first, then auth
	mux.HandleFunc("/api/v1/sessions", api.rateLimit(api.auth(api.handleSessions)))
	mux.HandleFunc("/api/v1/task", api.rateLimit(api.auth(api.handleTask)))
	return http.ListenAndServe(api.addr, mux)
}

// rateLimit is middleware that enforces per-IP rate limiting for the operator API.
func (api *API) rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}
		if !api.rateLimiter.Allow(clientIP) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// auth is a middleware that validates the Authorization: Bearer <key> header.
// If apiKey is empty, authentication is skipped (no-op).
// Uses crypto/subtle.ConstantTimeCompare to prevent timing attacks.
func (api *API) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if api.apiKey == "" {
			next(w, r)
			return
		}
		const prefix = "Bearer "
		header := r.Header.Get("Authorization")
		if len(header) < len(prefix) || subtle.ConstantTimeCompare([]byte(header[:len(prefix)]), []byte(prefix)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := header[len(prefix):]
		if subtle.ConstantTimeCompare([]byte(token), []byte(api.apiKey)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (api *API) handleSessions(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{"sessions": api.onList()})
}

type taskRequest struct {
	SessionID string `json:"session_id"`
	Type      uint8  `json:"type"`
	Data      string `json:"data"`
	Timeout   int    `json:"timeout"`
}

func (api *API) handleTask(w http.ResponseWriter, r *http.Request) {
	var req taskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if req.Timeout <= 0 {
		req.Timeout = int((60 * time.Second).Seconds())
	}
	if req.Timeout > 3600 {
		req.Timeout = 3600 // max 1 hour to prevent resource exhaustion
	}
	task, err := api.onTask(req.SessionID, req.Type, []byte(req.Data), req.Timeout)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"task": task})
}
