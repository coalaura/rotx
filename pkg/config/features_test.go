package config

import (
	"crypto/ecdh"
	"encoding/base32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResponsePolicyInheritance(t *testing.T) {
	fixture := newIdentityFixture(t)

	text := fixture.config(`
		server_tokens off;
		compress gzip brotli;
		location / { proxy_pass http://upstream; proxy_compress on; }
		location /reset { compress off; compress_cache off; server_tokens keep; return 200; }
	`)

	text = strings.Replace(text, "http {", "http { pow on; compress_memory_limit 2M; compress zstd; compress_cache memory; server_tokens full;", 1)

	compiled := compileFixture(t, fixture, text)
	route := compiled.Match(fixture.name, "/")
	policy := route.Compression()

	if !compiled.PoW() || compiled.CompressMemoryLimit() != 2<<20 || policy.Count != 2 || policy.Algorithms[0] != Gzip || policy.Algorithms[1] != Brotli || policy.Cache != CompressCacheMemory || route.ServerTokens() != TokensOff || !route.ProxyCompress() || route.Buffered() {
		t.Fatal("incorrect feature inheritance")
	}

	reset := compiled.Match(fixture.name, "/reset")
	if reset.Compression().Count != 0 || reset.Compression().Cache != CompressCacheOff || reset.ServerTokens() != TokensKeep {
		t.Fatal("explicit policy resets failed")
	}

	defaults := compileFixture(t, fixture, fixture.config(""))
	if defaults.PoW() || defaults.CompressMemoryLimit() != 32<<20 || defaults.Fallback("").Compression().Count != 0 || defaults.Fallback("").ServerTokens() != TokensAuto {
		t.Fatal("incorrect feature defaults")
	}
}

func TestFeatureScopeAndValidation(t *testing.T) {
	fixture := newIdentityFixture(t)

	invalid := []string{
		"pow on;", "compress_memory_limit 1M;", "proxy_compress on;", "proxy_buffer on;", "proxy_path /;",
		"compress gzip gzip;", "compress off gzip;", "compress br;", "compress_cache disk;", "server_tokens invalid;",
		"client_key missing.auth;", "client_keys missing;", "location / { client_key missing.auth; return 200; }",
		"location / { proxy_compress on; return 200; }", "location / { proxy_pass http://upstream; proxy_compress maybe; }",
	}

	for _, settings := range invalid {
		filename := filepath.Join(fixture.directory, "invalid.conf")

		writeFixture(t, filename, []byte(fixture.config(settings)))

		_, err := Load(filename)
		if err == nil {
			t.Fatalf("accepted invalid directives: %s", settings)
		}
	}

	global := []string{"pow maybe;", "compress_memory_limit 0;", "compress_memory_limit -1;", "compress_memory_limit 999999999999G;", "client_key missing.auth;", "proxy_compress on;"}

	for _, settings := range global {
		filename := filepath.Join(fixture.directory, "invalid.conf")
		text := strings.Replace(fixture.config(""), "http {", "http { "+settings, 1)

		writeFixture(t, filename, []byte(text))

		_, err := Load(filename)
		if err == nil {
			t.Fatalf("accepted invalid http directive: %s", settings)
		}
	}
}

func TestClientAuthorizationKeys(t *testing.T) {
	fixture := newIdentityFixture(t)

	scalar := [32]byte{7}

	private, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	key := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(private.PublicKey().Bytes())
	directory := filepath.Join(fixture.directory, "clients")

	err = os.Mkdir(directory, 0o700)
	if err != nil {
		t.Fatal(err)
	}

	writeFixture(t, filepath.Join(directory, "one.auth"), []byte("descriptor:x25519:"+key+"\n"))
	writeFixture(t, filepath.Join(directory, "duplicate.auth"), []byte("descriptor:x25519:"+strings.ToLower(key)))
	writeFixture(t, filepath.Join(directory, "ignored.txt"), []byte("invalid"))

	compiled := compileFixture(t, fixture, fixture.config("client_key clients/one.auth; client_keys clients; client_key clients/duplicate.auth; client_keys clients;"))

	for identity := range compiled.Identities() {
		if len(identity.ClientKeys) != 1 || identity.ClientKeys[0] != key {
			t.Fatalf("client key loading/deduplication failed: %v", identity.ClientKeys)
		}

		identity.ClientKeys[0] = "mutated"
	}

	for identity := range compiled.Identities() {
		if identity.ClientKeys[0] != key {
			t.Fatal("caller mutated compiled authorization")
		}
	}

	writeFixture(t, filepath.Join(directory, "one.auth"), []byte("invalid"))

	for identity := range compiled.Identities() {
		if identity.ClientKeys[0] != key {
			t.Fatal("client keys changed after configuration load")
		}
	}

	invalid := []string{"", "descriptor:x25519:" + strings.Repeat("A", 52), "descriptor:x25519:" + key + "extra", "descriptor:ed25519:" + key, "descriptor:x25519:" + key[:51] + "9"}

	for _, contents := range invalid {
		writeFixture(t, filepath.Join(directory, "one.auth"), []byte(contents))

		_, err = loadClientKey(filepath.Join(directory, "one.auth"))
		if err == nil {
			t.Fatalf("accepted invalid authorization key: %q", contents)
		}
	}

	writeFixture(t, filepath.Join(fixture.directory, "clients.conf"), []byte(fixture.config("client_keys clients;")))

	_, err = Load(filepath.Join(fixture.directory, "clients.conf"))
	if err == nil {
		t.Fatal("invalid explicit directory must fail closed")
	}

	empty := filepath.Join(fixture.directory, "empty")

	err = os.Mkdir(empty, 0o700)
	if err != nil {
		t.Fatal(err)
	}

	writeFixture(t, filepath.Join(fixture.directory, "clients.conf"), []byte(fixture.config("client_keys empty;")))

	_, err = Load(filepath.Join(fixture.directory, "clients.conf"))
	if err == nil {
		t.Fatal("empty explicit directory must fail closed")
	}
}
