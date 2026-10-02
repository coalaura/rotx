package main

import (
	"github.com/coalaura/plain"
	"github.com/coalaura/rotx/pkg/config"
)

const (
	ConfigPath = "config.yml"
)

var log = plain.New(plain.WithDate(plain.RFC3339Local))

func main() {
	log.Println("Loading config...")

	compiled, err := config.Load(ConfigPath)
	log.MustFail(err)

	log.Infof("Configuration valid: %d onion services", compiled.ServerCount())

	// serve
}
