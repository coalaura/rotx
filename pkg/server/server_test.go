package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coalaura/plain"
	"github.com/coalaura/rotx/pkg/config"
	"github.com/coalaura/rotx/pkg/router"
	"github.com/coalaura/rotx/pkg/tor"
)

const testTimeout = 5 * time.Second

type fakeTor struct {
	services   []tor.Service
	keys       [][]byte
	exit       chan error
	bootstrap  func(context.Context) error
	addError   error
	closeError error
	failAt     int
	closed     bool
}

type runningServer struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

type shutdownListener struct {
	net.Listener
	once   sync.Once
	closed chan struct{}
}

func (listener *shutdownListener) Close() error {
	listener.once.Do(func() {
		close(listener.closed)
	})

	return listener.Listener.Close()
}

func (instance *fakeTor) WaitBootstrap(ctx context.Context) error {
	if instance.bootstrap != nil {
		return instance.bootstrap(ctx)
	}

	return ctx.Err()
}

func (instance *fakeTor) AddOnion(ctx context.Context, service tor.Service) (*tor.Onion, error) {
	instance.services = append(instance.services, service)
	instance.keys = append(instance.keys, bytes.Clone(service.PrivateKey))

	if len(instance.services) == instance.failAt {
		return nil, instance.addError
	}

	return &tor.Onion{ID: service.ID}, ctx.Err()
}

func (instance *fakeTor) Wait(ctx context.Context) error {
	select {
	case err := <-instance.exit:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (instance *fakeTor) Close() error {
	instance.closed = true

	return instance.closeError
}

func (running *runningServer) wait(t *testing.T) error {
	t.Helper()

	waitSignal(t, running.done)

	return running.err
}

func TestServePublishesIdentitiesAndRoutesHTTP(t *testing.T) {
	compiled := testConfig(t, 2, "")

	listener := testListener(t)

	instance := &fakeTor{}
	ready := make(chan struct{})

	options := Options{Ready: func() {
		close(ready)
	}}

	running := startServer(t, compiled, options, instance, listener)

	waitSignal(t, ready)

	if len(instance.services) != 2 {
		t.Fatalf("registered %d services, want 2", len(instance.services))
	}

	transport := &http.Transport{}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: testTimeout}

	for index, service := range instance.services {
		if service.Target != listener.Addr().String() || service.Port != 80 {
			t.Fatalf("incorrect onion target: %#v", service)
		}

		if !bytes.Equal(service.PrivateKey, make([]byte, 64)) || len(instance.keys[index]) != 64 {
			t.Fatal("registration must receive an expanded key and clear it afterwards")
		}

		response := testRequest(t, client, listener.Addr().String(), service.ID+".onion:80")
		if response != service.ID {
			t.Fatalf("response %q, want %q", response, service.ID)
		}
	}

	running.cancel()

	err := running.wait(t)
	if err != nil || !instance.closed {
		t.Fatalf("shutdown: %v, Tor closed: %v", err, instance.closed)
	}

	assertListenerClosed(t, listener)
}

func TestServeAccessLogsAndRemovedStaticRoot(t *testing.T) {
	directory := t.TempDir()

	err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("static response"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	compiled := testConfig(t, 1, fmt.Sprintf("root %q;", filepath.ToSlash(directory)))

	listener := testListener(t)

	instance := &fakeTor{}

	ready := make(chan struct{})

	var output bytes.Buffer

	logger := plain.New(plain.WithTarget(&output))

	options := Options{
		Middleware: logger.Middleware(),
		Ready: func() {
			close(ready)
		},
	}

	running := startServer(t, compiled, options, instance, listener)

	waitSignal(t, ready)

	transport := &http.Transport{}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: testTimeout}

	host := instance.services[0].ID + ".onion"

	body := testRequest(t, client, listener.Addr().String(), host)
	if body != "static response" {
		t.Fatalf("unexpected static response %q", body)
	}

	err = os.RemoveAll(directory)
	if err != nil {
		t.Fatal(err)
	}

	request, err := http.NewRequest(http.MethodGet, "http://"+listener.Addr().String()+"/removed", nil)
	if err != nil {
		t.Fatal(err)
	}

	request.Host = host

	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	missingBody, err := io.ReadAll(response.Body)

	response.Body.Close()

	if err != nil || response.StatusCode != http.StatusNotFound || string(missingBody) != "Not Found\n" {
		t.Fatalf("removed root must respond with HTTP 404: %d, %q, %v", response.StatusCode, missingBody, err)
	}

	running.cancel()

	err = running.wait(t)
	if err != nil {
		t.Fatal(err)
	}

	logs := output.String()
	if strings.Count(logs, "\n") != 2 || !strings.Contains(logs, "GET    / 200 ") || !strings.Contains(logs, "GET    /removed 404 ") || strings.Count(logs, "127.0.0.1") != 2 {
		t.Fatalf("expected completed success and error access logs, got %q", logs)
	}
}

func TestServeRegistrationFailureCleansUp(t *testing.T) {
	compiled := testConfig(t, 2, "")

	listener := testListener(t)

	addError := errors.New("registration failed")
	closeError := errors.New("close failed")

	instance := &fakeTor{addError: addError, closeError: closeError, failAt: 2}

	var ready bool

	options := Options{Ready: func() {
		ready = true
	}}

	running := startServer(t, compiled, options, instance, listener)

	err := running.wait(t)
	if !errors.Is(err, addError) || !errors.Is(err, closeError) || ready || !instance.closed {
		t.Fatalf("partial startup: %v, ready: %v, closed: %v", err, ready, instance.closed)
	}

	if len(instance.services) != 2 {
		t.Fatal("test did not reach partial registration")
	}

	for _, service := range instance.services {
		if !bytes.Equal(service.PrivateKey, make([]byte, 64)) {
			t.Fatal("private key retained after failed registration")
		}
	}

	assertListenerClosed(t, listener)
}

func TestServeCancellationDuringBootstrap(t *testing.T) {
	compiled := testConfig(t, 1, "")

	listener := testListener(t)

	entered := make(chan struct{})

	closeError := errors.New("close failed")

	instance := &fakeTor{
		closeError: closeError,
		bootstrap: func(ctx context.Context) error {
			close(entered)
			<-ctx.Done()

			return ctx.Err()
		},
	}

	running := startServer(t, compiled, Options{}, instance, listener)

	waitSignal(t, entered)

	running.cancel()

	err := running.wait(t)
	if !errors.Is(err, closeError) || errors.Is(err, context.Canceled) || len(instance.services) != 0 || !instance.closed {
		t.Fatalf("bootstrap cancellation: %v, services: %d, closed: %v", err, len(instance.services), instance.closed)
	}

	assertListenerClosed(t, listener)
}

func TestServeTorExitDuringBootstrap(t *testing.T) {
	compiled := testConfig(t, 1, "")

	listener := testListener(t)

	entered := make(chan struct{})

	instance := &fakeTor{
		exit: make(chan error, 1),
		bootstrap: func(ctx context.Context) error {
			close(entered)
			<-ctx.Done()

			return ctx.Err()
		},
	}

	running := startServer(t, compiled, Options{}, instance, listener)

	waitSignal(t, entered)

	instance.exit <- nil

	err := running.wait(t)
	if err == nil || !strings.Contains(err.Error(), "exited unexpectedly") || !instance.closed {
		t.Fatalf("unexpected clean Tor exit: %v, closed: %v", err, instance.closed)
	}

	assertListenerClosed(t, listener)
}

func TestServeDetectsRuntimeFailures(t *testing.T) {
	failures := []string{"tor", "http"}

	for _, failure := range failures {
		t.Run(failure, func(t *testing.T) {
			compiled := testConfig(t, 1, "")

			listener := testListener(t)

			instance := &fakeTor{exit: make(chan error, 1)}
			ready := make(chan struct{})

			options := Options{Ready: func() {
				close(ready)
			}}

			running := startServer(t, compiled, options, instance, listener)

			waitSignal(t, ready)

			failureError := errors.New("Tor stopped")

			if failure == "tor" {
				instance.exit <- failureError
			} else {
				failureError = net.ErrClosed

				listener.Close()
			}

			err := running.wait(t)
			if !errors.Is(err, failureError) || !instance.closed {
				t.Fatalf("runtime failure: %v, closed: %v", err, instance.closed)
			}

			assertListenerClosed(t, listener)
		})
	}
}

func TestServeRevalidatesIdentityBeforeRegistration(t *testing.T) {
	compiled := testConfig(t, 1, "")

	listener := testListener(t)

	instance := &fakeTor{}

	for identity := range compiled.Identities() {
		err := os.WriteFile(identity.PrivateKeyPath, []byte("changed"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
	}

	running := startServer(t, compiled, Options{}, instance, listener)

	err := running.wait(t)
	if err == nil || !strings.Contains(err.Error(), "key_private") || len(instance.services) != 0 || !instance.closed {
		t.Fatalf("changed identity: %v, services: %d, closed: %v", err, len(instance.services), instance.closed)
	}
}

func TestServeDrainsActiveRequest(t *testing.T) {
	compiled := testConfig(t, 1, "location / { proxy_pass http://127.0.0.1:1; }")

	listener := &shutdownListener{Listener: testListener(t), closed: make(chan struct{})}

	instance := &fakeTor{}

	ready := make(chan struct{})
	entered := make(chan struct{})
	release := make(chan struct{})

	options := Options{
		Ready: func() {
			close(ready)
		},
		Handoffs: router.Handoffs{Proxy: func(response *router.Response, request *http.Request, target url.URL) error {
			close(entered)
			<-release

			_, err := io.WriteString(response, "drained")
			return err
		}},
	}

	running := startServer(t, compiled, options, instance, listener)
	defer close(release)

	waitSignal(t, ready)

	transport := &http.Transport{}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: testTimeout}

	request, err := http.NewRequest(http.MethodGet, "http://"+listener.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}

	request.Host = instance.services[0].ID + ".onion"

	requestDone := make(chan struct{})

	var (
		requestError error
		body         []byte
	)

	go func() {
		defer close(requestDone)

		response, err := client.Do(request)
		if err != nil {
			requestError = err

			return
		}

		defer response.Body.Close()

		body, requestError = io.ReadAll(response.Body)
	}()

	waitSignal(t, entered)

	running.cancel()

	waitSignal(t, listener.closed)

	select {
	case <-running.done:
		t.Fatal("server stopped before draining the active request")
	case release <- struct{}{}:
	}

	waitSignal(t, requestDone)

	if requestError != nil || string(body) != "drained" {
		t.Fatalf("active response interrupted: %q, %v", body, requestError)
	}

	err = running.wait(t)
	if err != nil || !instance.closed {
		t.Fatalf("drain: %v, closed: %v", err, instance.closed)
	}
}

func startServer(t *testing.T, compiled *config.Config, options Options, instance *fakeTor, listener net.Listener) *runningServer {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	running := &runningServer{
		cancel: cancel,
		done:   make(chan struct{}),
	}

	go func() {
		defer close(running.done)

		running.err = serve(ctx, compiled, options, instance, listener)
	}()

	t.Cleanup(func() {
		cancel()

		running.wait(t)
	})

	return running
}

func testConfig(t *testing.T, count int, route string) *config.Config {
	t.Helper()

	directory := t.TempDir()

	var text strings.Builder

	text.Grow(count*256 + 16)

	text.WriteString("http {")

	for index := range count {
		seed := bytes.Repeat([]byte{byte(index + 1)}, ed25519.SeedSize)

		private := ed25519.NewKeyFromSeed(seed)
		public := private.Public().(ed25519.PublicKey)

		expanded := sha512.Sum512(seed)

		expanded[0] &= 248
		expanded[31] &= 63
		expanded[31] |= 64

		checksumInput := append([]byte(".onion checksum"), public...)

		checksumInput = append(checksumInput, 3)

		checksum := sha3.Sum256(checksumInput)

		address := append(bytes.Clone(public), checksum[:2]...)

		address = append(address, 3)

		name := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(address))

		privateFile := append([]byte("== ed25519v1-secret: type0 ==\x00\x00\x00"), expanded[:]...)
		publicFile := append([]byte("== ed25519v1-public: type0 ==\x00\x00\x00"), public...)

		err := os.WriteFile(filepath.Join(directory, name+".private"), privateFile, 0o600)
		if err != nil {
			t.Fatal(err)
		}

		err = os.WriteFile(filepath.Join(directory, name+".public"), publicFile, 0o600)
		if err != nil {
			t.Fatal(err)
		}

		body := route
		if body == "" {
			body = fmt.Sprintf("location / { return 200 %s; }", name)
		}

		fmt.Fprintf(&text, "server { name %s; key_private %s.private; key_public %s.public; %s }", name, name, name, body)
	}

	text.WriteString("}")

	compiled, err := config.Compile([]byte(text.String()), filepath.Join(directory, "config.yml"))
	if err != nil {
		t.Fatal(err)
	}

	return compiled
}

func testListener(t *testing.T) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		listener.Close()
	})

	return listener
}

func testRequest(t *testing.T, client *http.Client, target, host string) string {
	t.Helper()

	request, err := http.NewRequest(http.MethodGet, "http://"+target, nil)
	if err != nil {
		t.Fatal(err)
	}

	request.Host = host

	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("HTTP response: %d, %v", response.StatusCode, err)
	}

	return string(body)
}

func assertListenerClosed(t *testing.T, listener net.Listener) {
	t.Helper()

	connection, err := net.DialTimeout("tcp", listener.Addr().String(), testTimeout)
	if err == nil {
		connection.Close()
		t.Fatal("HTTP listener remained open")
	}
}

func waitSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()

	select {
	case <-signal:
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for server")
	}
}
