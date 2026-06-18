package operator

import (
	"encoding/json"
	"net/http"
	"time"
)

type API struct {
	addr   string
	onList func() []string
	onTask func(sessionID string, taskType uint8, data []byte, timeout int) (interface{}, error)
}

func NewAPI(addr string, onList func() []string, onTask func(string, uint8, []byte, int) (interface{}, error)) *API {
	return &API{addr: addr, onList: onList, onTask: onTask}
}

func (api *API) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/sessions", api.handleSessions)
	mux.HandleFunc("/api/v1/task", api.handleTask)
	return http.ListenAndServe(api.addr, mux)
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
	if req.Timeout <= 0 { req.Timeout = int((60 * time.Second).Seconds()) }
	task, err := api.onTask(req.SessionID, req.Type, []byte(req.Data), req.Timeout)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"task": task})
}
