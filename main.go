package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

var Version = "dev"

func main() {
	if len(os.Args) > 1 && strings.EqualFold(os.Args[1], "version") {
		printVersion(os.Stdout)

		return
	}

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
			Log: func(level, message string) {
				writeTorLog(log, level, message)
			},
		},
		Handoffs: router.Handoffs{
			Error: func(request *http.Request, err error) {
				log.Errorf("HTTP %s %s: %v\n", request.Method, request.URL.Path, err)
			},
		},
		Middleware: log.Middleware(plain.WithHostAsPeer()),
		Ready: func() {
			for identity := range compiled.Identities() {
				log.Infof("Registered http://%s.onion; descriptor publication is asynchronous\n", identity.Name)
			}
		},
	}

	log.Println("Starting Tor...")

	err = server.Run(ctx, compiled, options)
	log.MustFail(err)
}
