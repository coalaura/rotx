//go:build (linux || windows) && cgo

package tor

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type nativeLogEntry struct {
	level   string
	message string
}

var coverageSummary = regexp.MustCompile(`\APASS\ncoverage: (?:(?:100\.0|[0-9]{1,2}\.[0-9])% of statements|\[no statements\])\n\z`)

func TestNativeLogCallback(t *testing.T) {
	// Tor is process-global and cannot be restarted after cleanup.
	if os.Getenv("ROTX_TEST_NATIVE_LOGS") == "1" {
		testNativeLogCallback(t)

		return
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	command := exec.CommandContext(ctx, executable, "-test.run=^TestNativeLogCallback$")
	command.Env = append(os.Environ(), "ROTX_TEST_NATIVE_LOGS=1")

	var standardError bytes.Buffer

	command.Stderr = &standardError

	output, err := command.Output()
	if err != nil {
		t.Fatalf("native logging subprocess: %v\n%s%s", err, output, standardError.Bytes())
	}

	if standardError.Len() != 0 {
		t.Fatalf("native console output outside the callback: %q", standardError.String())
	}

	// Only the test runner's exact success output is allowed, including its coverage summary.
	validOutput := string(output) == "PASS\n"

	if testing.CoverMode() != "" {
		validOutput = coverageSummary.Match(output)
	}

	if !validOutput {
		t.Fatalf("unexpected console output outside the callback: %q", output)
	}
}

func testNativeLogCallback(t *testing.T) {
	t.Helper()

	directory := t.TempDir()
	configuration := filepath.Join(directory, "torrc")

	err := os.WriteFile(configuration, nil, 0o600)
	if err != nil {
		t.Fatal(err)
	}

	arguments := []string{
		"tor", "-f", configuration,
		"--DataDirectory", directory,
		"--DisableNetwork", "1",
		"--SocksPort", "0",
		"--Log", "notice stderr",
		"--__DisableSignalHandlers", "1",
	}

	native, err := newNativeInstance(arguments)
	if err != nil {
		t.Fatal(err)
	}

	var mutex sync.Mutex

	entries := make([]nativeLogEntry, 0, 64)
	finished := make(chan struct{})

	var result int

	go func() {
		result = native.run(func(level, message string) {
			mutex.Lock()
			entries = append(entries, nativeLogEntry{level: level, message: message})
			mutex.Unlock()
		})

		close(finished)
	}()

	controller := newControl(native)
	events := make(chan Reply, 1)

	controller.event = func(reply Reply) {
		if len(reply.Lines) > 0 && reply.Lines[0] == "CONF_CHANGED" {
			events <- reply
		}
	}

	t.Cleanup(func() {
		controller.close()

		select {
		case <-finished:
			native.free()
		case <-time.After(10 * time.Second):
			t.Error("native Tor did not stop")
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = controller.command(ctx, "SETEVENTS HS_DESC CONF_CHANGED")
	if err != nil {
		t.Fatalf("subscribe to native events: %v", err)
	}

	_, err = controller.command(ctx, `SETCONF Log="info stderr"`)
	if err != nil {
		t.Fatalf("reconfigure logging: %v", err)
	}

	// No command is in flight: the reader must still deliver native events.
	select {
	case event := <-events:
		value, ok := event.Value("Log")
		if !ok || value != "info stderr" {
			t.Fatalf("native configuration event = %+v", event)
		}
	case <-ctx.Done():
		t.Fatal("native control event was not delivered while idle")
	}

	_, err = controller.command(ctx, "SIGNAL SHUTDOWN")
	if err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	if result != 0 {
		t.Fatalf("native exit status: %d", result)
	}

	var (
		startupCount int
		shutdown     bool
	)

	for _, entry := range entries {
		if strings.ContainsAny(entry.message, "\r\n") {
			t.Errorf("callback message contains a line ending: %q", entry.message)
		}

		switch entry.level {
		case "debug", "info", "notice", "warn", "err":
		default:
			t.Errorf("unknown severity: %q", entry.level)
		}

		if strings.HasPrefix(entry.message, "Tor 0.") && entry.level == "notice" {
			startupCount++
		}

		if strings.Contains(entry.message, "exiting cleanly") && entry.level == "notice" {
			shutdown = true
		}
	}

	if startupCount != 1 || !shutdown {
		t.Fatalf("missing or duplicated timestamp-free lifecycle logs: startup=%d shutdown=%t entries=%+v", startupCount, shutdown, entries)
	}
}
