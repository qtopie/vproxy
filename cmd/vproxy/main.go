package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	vlink "github.com/qtopie/vproxy/internal"
)

var (
	configPath = flag.String("c", "vproxy.json", "path to config file")
	verbose    = flag.Bool("v", false, "verbose mode")
	localHTTP  = flag.Int("http", 8118, "local HTTP proxy port")
	localSocks = flag.Int("socks", 1080, "local SOCKS5 proxy port")
	localTrans = flag.Int("trans", 10080, "local transparent proxy port")
)

func main() {
	flag.Parse()

	cfg, finalPath, err := vlink.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	isVerbose := (verbose != nil && *verbose) || os.Getenv("VP_VERBOSE") == "1"
	if isVerbose {
		vlink.SetVerbose(true)
	}

	logPath := fmt.Sprintf("/tmp/vproxy-%d.log", os.Getpid())
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		vlink.SetOutput(f)
		// We don't Close(f) here because the logger needs it. 
		// The OS will close it when the process exits.
		fmt.Fprintf(os.Stderr, "Logging to %s\n", logPath)
	} else {
		log.Printf("Failed to open log file %s: %v", logPath, err)
	}

	vproxy := &vlink.App{
		Config:     cfg,
		ConfigPath: finalPath,
		LocalSocks: *localSocks,
		LocalHTTP:  *localHTTP,
		LocalTrans: *localTrans,
	}

	args := flag.Args()
	if len(args) > 0 {
		vproxy.RunWrapper(args)
		return
	}

	vproxy.RunServer()
}
