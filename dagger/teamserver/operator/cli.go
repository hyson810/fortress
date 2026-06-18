package operator

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

type CLI struct {
	reader   *bufio.Reader
	onTask   func(sessionID string, taskType uint8, data []byte, timeout int) (interface{}, error)
	onList   func() []string
}

func NewCLI(onList func() []string, onTask func(string, uint8, []byte, int) (interface{}, error)) *CLI {
	return &CLI{reader: bufio.NewReader(os.Stdin), onList: onList, onTask: onTask}
}

func (cli *CLI) Run() {
	fmt.Println("Hydra-Pro Operator Console")
	fmt.Println("Type 'help' for commands, 'exit' to quit")
	for {
		fmt.Print("hydra> ")
		line, _ := cli.reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" { continue }
		parts := strings.Fields(line)
		switch parts[0] {
		case "help": cli.cmdHelp()
		case "sessions": cli.cmdSessions()
		case "shell":
			if len(parts) < 3 { fmt.Println("usage: shell <session_id> <command>"); continue }
			cli.cmdShell(parts[1], strings.Join(parts[2:], " "))
		case "exit": return
		default: fmt.Printf("unknown: %s (type 'help')\n", parts[0])
		}
	}
}

func (cli *CLI) cmdHelp() {
	fmt.Println(`Commands:
  help         Show this help
  sessions     List active sessions
  shell <id> <cmd>  Execute command on implant
  exit         Quit`)
}
func (cli *CLI) cmdSessions() {
	sessions := cli.onList()
	if len(sessions) == 0 { fmt.Println("(no active sessions)"); return }
	for _, s := range sessions { fmt.Printf("  %s\n", s) }
}
func (cli *CLI) cmdShell(sessionID, command string) {
	cli.onTask(sessionID, 1, []byte(command), int((60 * time.Second).Seconds()))
	fmt.Printf("task queued for %s: shell %s\n", sessionID, command)
}
