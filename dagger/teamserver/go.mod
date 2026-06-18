module github.com/fortress/hydra-pro/dagger/teamserver

go 1.26.4

require (
	golang.org/x/crypto v0.24.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/gorilla/websocket v1.5.3
	golang.org/x/sys v0.21.0 // indirect
)

replace github.com/gorilla/websocket v1.5.3 => ./_local/github.com/gorilla/websocket
