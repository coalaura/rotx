//go:build (linux || windows) && cgo

package tor

import (
	"strings"
	"testing"
)

func TestLibraryVersions(t *testing.T) {
	started := torStarted.Load()

	info := Versions()

	if torStarted.Load() != started {
		t.Fatal("reading library versions started Tor")
	}

	if info.Tor == "" || info.Tor != Version() {
		t.Fatalf("Tor version does not match the linked library: %q", info.Tor)
	}

	versions := []string{info.OpenSSL, info.Libevent, info.Zlib}

	for _, version := range versions {
		if version == "" || strings.ContainsAny(version, "\r\n") {
			t.Fatalf("invalid native version %q in %+v", version, info)
		}
	}
}
