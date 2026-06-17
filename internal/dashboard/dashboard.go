package dashboard

import (
	"context"
	"embed"
	"io/fs"
	"net/http"
	"sync"
	"time"
)

//go:embed assets
var assetsFS embed.FS

// Dashboard is the optional visualization HTTP server.
type Dashboard struct {
	config  Config
	server  *http.Server
	mux     *http.ServeMux
	hub     *Hub
	brain   BrainProvider
	started bool
	mu      sync.Mutex
}

// BrainProvider is the interface the dashboard needs from the brain/scorer.
type BrainProvider interface {
	Top(n int) []interface{}
	GetScore(ip string) (float64, string)
	Count() int
	GetMetrics() map[string]interface{}
}

// New creates a new Dashboard server.
func New(cfg Config, brain BrainProvider) *Dashboard {
	mux := http.NewServeMux()
	return &Dashboard{
		config: cfg,
		mux:    mux,
		hub:    NewHub(),
		brain:  brain,
	}
}

// Start launches the HTTP server in the background.
func (d *Dashboard) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.started {
		return nil
	}

	d.registerRoutes()

	// Serve embedded assets
	assetsSub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		return err
	}
	d.mux.Handle("/", http.FileServer(http.FS(assetsSub)))

	d.server = &http.Server{
		Addr:    ":" + itoa(d.config.Port),
		Handler: d.mux,
	}

	go func() {
		if err := d.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// server error logged but not fatal
		}
	}()

	if d.config.Enabled {
		go d.pushLoop()
	}

	d.started = true
	return nil
}

// Stop gracefully shuts down the HTTP server.
func (d *Dashboard) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.started {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d.hub.Stop()
	d.started = false
	return d.server.Shutdown(ctx)
}

// Started reports whether the server is currently running.
func (d *Dashboard) Started() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.started
}

// itoa converts an int to a decimal string (avoids strconv import).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
