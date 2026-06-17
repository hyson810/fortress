package dashboard

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Hub manages all SSE client connections.
type Hub struct {
	clients map[chan []byte]struct{}
	mu      sync.RWMutex
	stopCh  chan struct{}
}

// NewHub creates a new Hub.
func NewHub() *Hub {
	return &Hub{
		clients: make(map[chan []byte]struct{}),
		stopCh:  make(chan struct{}),
	}
}

// Register adds a new client channel and returns it.
func (h *Hub) Register() chan []byte {
	ch := make(chan []byte, 64)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

// Unregister removes a client channel.
func (h *Hub) Unregister(ch chan []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Only close if still registered — Stop() may have already removed and closed it.
	if _, ok := h.clients[ch]; ok {
		delete(h.clients, ch)
		close(ch)
	}
}

// Broadcast sends a message to all connected clients.
func (h *Hub) Broadcast(msg WSMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.clients {
		select {
		case ch <- data:
		default:
			// client too slow, skip
		}
	}
}

// Stop closes all client channels and shuts down the hub.
func (h *Hub) Stop() {
	select {
	case <-h.stopCh:
		return
	default:
		close(h.stopCh)
	}
	h.mu.Lock()
	for ch := range h.clients {
		close(ch)
	}
	h.clients = make(map[chan []byte]struct{})
	h.mu.Unlock()
}

// handleWebSocket serves Server-Sent Events (SSE) for real-time updates.
func (d *Dashboard) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Write initial comment to flush headers and confirm connection.
	w.Write([]byte(": connected\n\n"))
	flusher.Flush()

	ch := d.hub.Register()
	defer d.hub.Unregister(ch)

	for {
		select {
		case <-r.Context().Done():
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			w.Write([]byte("data: "))
			w.Write(data)
			w.Write([]byte("\n\n"))
			flusher.Flush()
		}
	}
}

// pushLoop periodically broadcasts pipeline stats to all connected clients.
func (d *Dashboard) pushLoop() {
	ticker := time.NewTicker(time.Duration(d.config.RefreshInterval) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-d.hub.stopCh:
			return
		case <-ticker.C:
			count := d.brain.Count()
			d.hub.Broadcast(WSMessage{
				Type: "pipeline_tick",
				Data: map[string]interface{}{
					"active_threats": count,
					"timestamp":      time.Now().Unix(),
				},
			})
		}
	}
}
