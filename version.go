package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/coalaura/rotx/pkg/tor"
)

func printVersion(output io.Writer) {
	fmt.Fprintf(output, "rotx version %s\n\n", Version)

	native := tor.Versions()

	if native.Tor == "" {
		fmt.Fprintln(output, "  Embedded Tor: unavailable (requires cgo on Linux or Windows)")
	} else {
		fmt.Fprintf(output, "  Tor:      %s\n  OpenSSL:  %s\n  Libevent: %s\n  zlib:     %s\n", strings.TrimPrefix(native.Tor, "tor "), native.OpenSSL, native.Libevent, native.Zlib)
	}
}
