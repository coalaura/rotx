package main

import (
	"bytes"
	"testing"

	"github.com/coalaura/plain"
)

func TestWriteTorLog(t *testing.T) {
	levels := []string{"debug", "info", "notice", "warn", "err"}

	for _, level := range levels {
		t.Run(level, func(t *testing.T) {
			var output bytes.Buffer

			logger := plain.New(plain.WithTarget(&output), plain.WithDate("timestamp"))

			writeTorLog(logger, level, "Bootstrapped 100% (done): Done")

			want := "timestamp [tor/" + level + "] Bootstrapped 100% (done): Done\n"
			if output.String() != want {
				t.Fatalf("log output = %q, want %q", output.String(), want)
			}
		})
	}
}
