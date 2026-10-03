package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/coalaura/plain"
	"github.com/coalaura/rotx/pkg/config"
	"github.com/coalaura/rotx/pkg/router"
	"github.com/coalaura/rotx/pkg/server"
	"github.com/coalaura/rotx/pkg/tor"
)

const (
	ConfigPath       = "rotx.conf"
	TorDataDirectory = "data/tor"
)

var log = plain.New(plain.WithDate(plain.RFC3339Local))

func main() {
	log.Println("Loading config...")

	compiled, err := config.Load(ConfigPath)
	log.MustFail(err)

	log.Infof("Configuration valid: %d onion services\n", compiled.ServerCount())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	options := server.Options{
		Tor: tor.Options{
			DataDirectory: TorDataDirectory,
			LogLevel:      "notice",
		},
		Handoffs: router.Handoffs{
			Error: func(request *http.Request, err error) {
				log.Errorf("HTTP %s %s: %v\n", request.Method, request.URL.Path, err)
			},
		},
		Ready: func() {
			for identity := range compiled.Identities() {
				log.Infof("Serving http://%s.onion\n", identity.Name)
			}
		},
	}

	log.Println("Starting Tor...")

	err = server.Run(ctx, compiled, options)
	log.MustFail(err)
}
