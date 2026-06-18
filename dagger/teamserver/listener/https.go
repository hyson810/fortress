package listener

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"time"
)

type Callback func(transport string, data []byte) ([]byte, error)

type HTTPSListener struct {
	addr     string
	certFile string
	keyFile  string
	server   *http.Server
	OnData   Callback
}

func NewHTTPSListener(addr, certFile, keyFile string, cb Callback) *HTTPSListener {
	l := &HTTPSListener{
		addr:     addr,
		certFile: certFile,
		keyFile:  keyFile,
		OnData:   cb,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", l.handleCheckin)
	mux.HandleFunc("/health", l.handleHealth)
	l.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return l
}

func (l *HTTPSListener) Start() error {
	log.Printf("[listener/https] starting on %s", l.addr)
	if l.certFile != "" && l.keyFile != "" {
		return l.server.ListenAndServeTLS(l.certFile, l.keyFile)
	}
	return l.server.ListenAndServe()
}

func (l *HTTPSListener) handleCheckin(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	resp, err := l.OnData("https", data)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(resp)
}

func (l *HTTPSListener) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Write([]byte("ok"))
}
