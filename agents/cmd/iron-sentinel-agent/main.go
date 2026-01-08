package main

import (
	"flag"
	"log"
	"time"

	"iron-sentinel/agents/internal/agent"
)

func main() {
	var serverURL string
	var psk string
	var insecure bool
	var poll time.Duration
	var triageBin string
	var outputBase string

	flag.StringVar(&serverURL, "server", "https://127.0.0.1:8443", "Server base URL")
	flag.StringVar(&psk, "psk", "", "Pre-shared key (X-PSK)")
	flag.BoolVar(&insecure, "insecure", true, "Skip TLS certificate verification (lab mode)")
	flag.DurationVar(&poll, "poll", 10*time.Second, "Poll interval")
	flag.StringVar(&triageBin, "triage-bin", "./iron-sentinel", "Path to iron-sentinel binary")
	flag.StringVar(&outputBase, "output", "./agent-evidence", "Local output base directory")
	flag.Parse()

	cfg := agent.Config{
		ServerURL:   serverURL,
		PSK:         psk,
		InsecureTLS: insecure,
		PollEvery:   poll,
		TriageBin:   triageBin,
		OutputBase:  outputBase,
	}

	if err := agent.Run(cfg); err != nil {
		log.Fatal(err)
	}
}
