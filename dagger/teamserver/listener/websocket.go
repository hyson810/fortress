package listener

import (
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

type WSListener struct {
	addr     string
	OnData   Callback
	upgrader websocket.Upgrader
}

func NewWSListener(addr string, cb Callback) *WSListener {
	return &WSListener{
		addr:   addr,
		OnData: cb,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (l *WSListener) Start() error {
	http.HandleFunc("/ws", l.handleWS)
	log.Printf("[listener/ws] starting on %s", l.addr)
	return http.ListenAndServe(l.addr, nil)
}

func (l *WSListener) handleWS(w http.ResponseWriter, r *http.Request) {
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
