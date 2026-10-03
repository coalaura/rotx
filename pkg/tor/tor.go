package tor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	bootstrapPollInterval = 250 * time.Millisecond
	defaultCloseTimeout   = 15 * time.Second
)

type Options struct {
	DataDirectory string
	LogLevel      string

	// Log receives timestamp-free Tor messages synchronously, including startup
	// and shutdown logs. It must be concurrency-safe and must not call Tor APIs.
	// When nil, Tor writes to its usual stdout/stderr destinations.
	Log func(level, message string)
}

type Instance struct {
	native    *nativeInstance
	control   *control
	runDone   chan struct{}
	closeDone chan struct{}

	closeOnce sync.Once
	errMutex  sync.Mutex
	closeErr  error
	runErr    error
}

var torStarted atomic.Bool

func (instance *Instance) WaitBootstrap(ctx context.Context) error {
	ticker := time.NewTicker(bootstrapPollInterval)
	defer ticker.Stop()

	for {
		progress, err := instance.bootstrapProgress(ctx)
		if err != nil {
			return err
		}

		if progress == 100 {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-instance.runDone:
			return instance.exitError("Tor exited during bootstrap")
		case <-ticker.C:
		}
	}
}

func (instance *Instance) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-instance.runDone:
		return instance.exitError("")
	}
}

func (instance *Instance) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
	defer cancel()

	return instance.CloseContext(ctx)
}

// CloseContext starts shutdown once and waits up to the caller's deadline.
// Native cleanup continues in the background if the caller stops waiting.
func (instance *Instance) CloseContext(ctx context.Context) error {
	instance.closeOnce.Do(func() {
		// Cleanup outlives a caller's deadline, including freeing the native instance.
		go instance.shutdown(ctx)
	})

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-instance.closeDone:
	}

	instance.errMutex.Lock()
	closeError := instance.closeErr
	runError := instance.runErr
	instance.errMutex.Unlock()

	return errors.Join(closeError, runError)
}

func (instance *Instance) shutdown(ctx context.Context) {
	shutdownContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	_, signalErr := instance.control.command(shutdownContext, "SIGNAL SHUTDOWN")
	if errors.Is(signalErr, net.ErrClosed) {
		// A cancelled exchange may already have closed the owning controller.
		signalErr = nil
	}

	instance.errMutex.Lock()
	instance.closeErr = signalErr
	instance.errMutex.Unlock()

	// Closing the owning controller interrupts commands and removes its onion services.
	instance.control.close()
	<-instance.runDone
	instance.native.free()
	close(instance.closeDone)
}

func (instance *Instance) bootstrapProgress(ctx context.Context) (int, error) {
	reply, err := instance.control.command(ctx, "GETINFO status/bootstrap-phase")
	if err != nil {
		return 0, err
	}

	status, ok := reply.Value("status/bootstrap-phase")
	if !ok {
		return 0, fmt.Errorf("tor bootstrap reply did not contain status/bootstrap-phase")
	}

	for field := range strings.FieldsSeq(status) {
		value, found := strings.CutPrefix(field, "PROGRESS=")
		if !found {
			continue
		}

		progress, parseError := strconv.Atoi(value)
		if parseError != nil || progress < 0 || progress > 100 {
			return 0, fmt.Errorf("invalid Tor bootstrap progress %q", value)
		}

		return progress, nil
	}

	return 0, fmt.Errorf("tor bootstrap reply did not contain PROGRESS")
}

func (instance *Instance) exitError(fallback string) error {
	instance.errMutex.Lock()
	runError := instance.runErr
	instance.errMutex.Unlock()

	if runError != nil {
		return runError
	}

	if fallback != "" {
		return errors.New(fallback)
	}

	return nil
}

func Version() string {
	return nativeVersion()
}

func Start(options Options) (*Instance, error) {
	if options.DataDirectory == "" {
		return nil, fmt.Errorf("tor data directory is required")
	}

	if !torStarted.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("embedded Tor can only be started once per process")
	}

	var started bool

	defer func() {
		if !started {
			torStarted.Store(false)
		}
	}()

	err := os.MkdirAll(options.DataDirectory, 0o700)
	if err != nil {
		return nil, fmt.Errorf("create Tor data directory: %w", err)
	}

	torrcPath := filepath.Join(options.DataDirectory, "rotx.torrc")

	err = writeEmptyTorrc(torrcPath)
	if err != nil {
		return nil, err
	}

	arguments := []string{
		"tor",
		"-f", torrcPath,
		"--DataDirectory", options.DataDirectory,
		"--SocksPort", "0",
		"--__DisableSignalHandlers", "1",
	}

	if options.LogLevel != "" {
		arguments = append(arguments, "--Log", options.LogLevel+" stderr")
	}

	native, err := newNativeInstance(arguments)
	if err != nil {
		return nil, err
	}

	instance := &Instance{
		native:    native,
		control:   newControl(native),
		runDone:   make(chan struct{}),
		closeDone: make(chan struct{}),
	}

	started = true

	go func() {
		code := native.run(options.Log)

		instance.errMutex.Lock()

		if code != 0 {
			instance.runErr = fmt.Errorf("embedded Tor exited with status %d", code)
		}

		instance.errMutex.Unlock()

		close(instance.runDone)
	}()

	return instance, nil
}

func writeEmptyTorrc(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create embedded Tor configuration: %w", err)
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf("close embedded Tor configuration: %w", err)
	}

	return nil
}
