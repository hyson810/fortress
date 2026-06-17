package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	configPath = flag.String("config", "/etc/fortress/fortress.yaml", "path to config file")
	mode       = flag.String("mode", "defend", "operating mode: defend, scan, fusion, counterstrike, serve-mcp")
)

func main() {
	flag.Parse()
	fmt.Fprintf(os.Stderr, "Fortress V6 — %s mode\n", *mode)
	os.Exit(0)
}
