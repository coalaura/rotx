package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/coalaura/rotx/pkg/tor"
)

func TestPrintVersion(t *testing.T) {
	var output bytes.Buffer

	printVersion(&output)

	text := output.String()
	if !strings.HasPrefix(text, "rotx version "+Version+"\n") {
		t.Fatalf("missing rotx version: %q", text)
	}

	if strings.Contains(text, "Go ") || strings.Contains(text, "Native build:") {
		t.Fatalf("unexpected Go libraries or build settings: %q", text)
	}

	if tor.Version() == "" {
		if !strings.Contains(text, "Embedded Tor: unavailable") {
			t.Fatalf("unsupported native build not identified: %q", text)
		}

		return
	}

	labels := []string{"  Tor:      ", "  OpenSSL:  ", "  Libevent: ", "  zlib:     "}

	for _, label := range labels {
		_, following, found := strings.Cut(text, "\n"+label)
		if !found || following == "" || following[0] == '\n' {
			t.Errorf("missing version for %s in %q", label, text)
		}
	}
}
