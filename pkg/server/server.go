// Package server connects the HTTP router to embedded Tor onion services.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/coalaura/rotx/pkg/config"
	"github.com/coalaura/rotx/pkg/router"
	"github.com/coalaura/rotx/pkg/tor"
)

const (
	onionPort         = 80
	readHeaderTimeout = 30 * time.Second
	idleTimeout       = 2 * time.Minute
	shutdownTimeout   = 30 * time.Second
)

type Options struct {
	Tor        tor.Options
	Handoffs   router.Handoffs
	Middleware func(http.Handler) http.Handler
	// Ready runs after local HTTP startup and onion registration. Descriptor
	// publication and client reachability are not guaranteed at this point.
	Ready func()
}

type torInstance interface {
	WaitBootstrap(context.Context) error
	AddOnion(context.Context, tor.Service) (*tor.Onion, error)
	Wait(context.Context) error
	Close() error
}

// Run publishes every configured identity on port 80 and serves until ctx is
// canceled or Tor/HTTP fails. Cancellation drains HTTP requests before closing Tor.
func Run(ctx context.Context, compiled *config.Config, options Options) error {
	if compiled == nil || compiled.ServerCount() == 0 {
		return fmt.Errorf("at least one configured onion service is required")
	}

	if ctx.Err() != nil {
		return nil
	}

	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen for Tor connections: %w", err)
	}

	instance, err := tor.Start(options.Tor)
	if err != nil {
		listener.Close()

		return fmt.Errorf("start Tor: %w", err)
	}

	return serve(ctx, compiled, options, instance, listener)
}

func serve(ctx context.Context, compiled *config.Config, options Options, instance torInstance, listener net.Listener) (result error) {
	handler := router.New(compiled, options.Handoffs)

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}

	if options.Middleware != nil {
		server.Handler = options.Middleware(handler)
	}

	runContext, cancel := context.WithCancelCause(ctx)

	torDone := make(chan struct{})
	httpDone := make(chan struct{})

	go func() {
		defer close(torDone)

		err := instance.Wait(runContext)

		if runContext.Err() != nil {
			return
		}

		if err == nil {
			err = fmt.Errorf("tor exited unexpectedly")
		}

		cancel(err)
	}()

	go func() {
		defer close(httpDone)

		err := server.Serve(listener)

		cancel(fmt.Errorf("serve HTTP: %w", err))
	}()

	defer func() {
		if ctx.Err() != nil && errors.Is(result, ctx.Err()) {
			result = nil
		}

		cancel(nil)
		<-torDone

		// Keep Tor alive while in-flight HTTP responses drain. Request contexts
		// are deliberately independent of the canceled startup/lifetime context.
		shutdownContext, stop := context.WithTimeout(context.Background(), shutdownTimeout)
		defer stop()

		err := server.Shutdown(shutdownContext)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("drain HTTP: %w", err), server.Close())
		}

		// Shutdown can race with Serve before it has registered the listener.
		listener.Close()

		<-httpDone

		handler.CloseIdleConnections()

		err = instance.Close()
		if err != nil {
			result = errors.Join(result, fmt.Errorf("close Tor: %w", err))
		}
	}()

	err := instance.WaitBootstrap(runContext)
	if err != nil {
		return startupError(runContext, "bootstrap Tor", err)
	}

	target := listener.Addr().String()

	for identity := range compiled.Identities() {
		private, err := identity.LoadPrivateKey()
		if err != nil {
			return fmt.Errorf("load onion %s: %w", identity.Name, err)
		}

		service := tor.Service{
			ID:         identity.Name,
			Target:     target,
			PrivateKey: private,
			Port:       onionPort,
		}

		_, err = instance.AddOnion(runContext, service)

		clear(private)

		if err != nil {
			return startupError(runContext, "register onion "+identity.Name, err)
		}
	}

	if runContext.Err() == nil && options.Ready != nil {
		options.Ready()
	}

	<-runContext.Done()

	return context.Cause(runContext)
}

func startupError(ctx context.Context, operation string, err error) error {
	cause := context.Cause(ctx)
	if cause != nil {
		return cause
	}

	return fmt.Errorf("%s: %w", operation, err)
}
