package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type identityFixture struct {
	name      string
	directory string
	private   ed25519.PrivateKey
	public    ed25519.PublicKey
}

type routeCase struct {
	path string
	body string
}

type invalidConfigCase struct {
	name string
	text string
	want string
}

type staticCase struct {
	path   string
	target string
}

func (fixture identityFixture) config(body string) string {
	return fmt.Sprintf(`http { server { name %s; key_private private.pem; key_public public.pem; %s } }`, fixture.name, body)
}

func TestCompiledRouting(t *testing.T) {
	fixture := newIdentityFixture(t)
	text := fixture.config(`
		location /foo { return 200 "prefix"; }
		location /foobar { return 200 "longer"; }
		location = /foo/exact { return 200 "exact"; }
		location ^~ /protected { return 200 "protected"; }
		location /protected/open { return 200 "open"; }
		location ~ "^/(foo|protected)/.*" { return 200 "first regex"; }
		location ~ "foo" { return 200 "second regex"; }
		location /bar { return 200 "bar"; }
	`)
	compiled := compileFixture(t, fixture, text)
	cases := []routeCase{
		{path: "/foo/exact", body: "exact"},
		{path: "/foo/other", body: "first regex"},
		{path: "/foobar", body: "second regex"},
		{path: "/protected/other", body: "protected"},
		{path: "/protected/open/other", body: "first regex"},
		{path: "/barbaz", body: "bar"},
	}

	for _, test := range cases {
		route := compiled.Match(fixture.name, test.path)
		if route == nil || route.Body() != test.body {
			t.Fatalf("%s: got %#v, want %q", test.path, route, test.body)
		}
	}

	if compiled.Match(fixture.name, "/missing").Kind() != NotFound || compiled.Match("unknown", "/") != nil {
		t.Fatal("incorrect fallback")
	}

	plain := compileFixture(t, fixture, fixture.config(`location /foo { return 200 "prefix"; } location /foobar { return 200 "longer"; }`))
	if plain.Match(fixture.name, "/foobarbaz").Body() != "longer" || plain.Match(fixture.name, "/fooz").Body() != "prefix" {
		t.Fatal("longest prefix or non-segment prefix matching failed")
	}
}

func TestInheritanceAndTargets(t *testing.T) {
	fixture := newIdentityFixture(t)
	text := fixture.config(`
		alias files;
		cache 2h;
		index first.htm second.htm;
		header_unset Example;
		header_set example server;
		location /assets/ { alias assets; cache auto; header_add EXAMPLE extra; }
		location = /exact { alias single; }
		location = /inherited { }
		location ~ "^/regex" { }
		location /parent { root other; cache off; }
		location /parent/child { }
		location /proxy { proxy_pass http://localhost:8080/base/; proxy_buffer on; }
		location /fixed { proxy_pass https://localhost/base; proxy_path /fixed%20path; }
	`)
	text = strings.Replace(text, "http {", `http { header_set Example global; header_add Example global-extra;`, 1)
	compiled := compileFixture(t, fixture, text)
	cases := []staticCase{
		{path: "/fallback", target: "files/fallback"},
		{path: "/assets/pic.png", target: "assets/pic.png"},
		{path: "/exact", target: "single"},
		{path: "/inherited", target: "files/inherited"},
		{path: "/regex/file", target: "files/regex/file"},
		{path: "/parent/child/file", target: "files/parent/child/file"},
	}

	for _, test := range cases {
		route := compiled.Match(fixture.name, test.path)

		target, err := route.StaticPath(test.path)
		if err != nil || target != filepath.Join(fixture.directory, filepath.FromSlash(test.target)) {
			t.Fatalf("%s: %q, %v", test.path, target, err)
		}
	}

	assets := compiled.Match(fixture.name, "/assets/file")
	headers := make(http.Header)
	headers.Set("Example", "upstream")
	assets.ApplyHeaders(headers)

	if strings.Join(headers.Values("Example"), ",") != "server,extra" || assets.Cache().Mode != CacheAuto || assets.IndexCount() != 2 || assets.Index(1) != "second.htm" {
		t.Fatalf("incorrect inherited policy: %#v, %#v", headers, assets)
	}

	child := compiled.Match(fixture.name, "/parent/child/file")
	if child.Cache().Seconds != 7200 {
		t.Fatal("location inherited from another location instead of server")
	}

	proxy := compiled.Match(fixture.name, "/proxy/file")
	upstream := proxy.ProxyURL("/proxy/file", "q=a%2Fb")

	if upstream.String() != "http://localhost:8080/base/proxy/file?q=a%2Fb" || !proxy.Buffered() {
		t.Fatalf("unexpected proxy target %s", upstream.String())
	}

	fixed := compiled.Match(fixture.name, "/fixed/ignored")
	upstream = fixed.ProxyURL("/fixed/ignored", "x=1")

	if upstream.String() != "https://localhost/fixed%20path?x=1" || fixed.Buffered() {
		t.Fatalf("unexpected fixed target %s", upstream.String())
	}
}

func TestTextualIncludes(t *testing.T) {
	fixture := newIdentityFixture(t)
	writeFixture(t, filepath.Join(fixture.directory, "start.conf"), []byte(`http { header_set Example global;`))
	writeFixture(t, filepath.Join(fixture.directory, "server.conf"), []byte(fmt.Sprintf(`server { name %s; key_private private.pem; key_public public.pem; include parts/*.conf; }`, fixture.name)))

	err := os.Mkdir(filepath.Join(fixture.directory, "parts"), 0700)
	if err != nil {
		t.Fatal(err)
	}

	writeFixture(t, filepath.Join(fixture.directory, "parts", "10.conf"), []byte(`header_set Example first; root files;`))
	writeFixture(t, filepath.Join(fixture.directory, "parts", "20.conf"), []byte(`header_add Example second; location / { include ../return.conf; }`))
	writeFixture(t, filepath.Join(fixture.directory, "return.conf"), []byte(`return 200 "included";`))
	compiled := compileFixture(t, fixture, `include start.conf; include server.conf; }`)
	route := compiled.Match(fixture.name, "/")
	headers := make(http.Header)
	route.ApplyHeaders(headers)

	if route.Body() != "included" || strings.Join(headers.Values("Example"), ",") != "first,second" {
		t.Fatalf("textual/glob include ordering failed: %q %#v", route.Body(), headers)
	}

	fallback := compiled.Match(fixture.name, "outside")

	target, err := fallback.StaticPath("/file")
	if err != nil || target != filepath.Join(fixture.directory, "parts", "files", "file") {
		t.Fatalf("filesystem path did not use containing file: %s %v", target, err)
	}

	writeFixture(t, filepath.Join(fixture.directory, "return.conf"), []byte("return 200;\nheader_set X late;"))

	_, err = Compile([]byte(`include start.conf; include server.conf; }`), filepath.Join(fixture.directory, "rotx.conf"))
	if err == nil || !strings.Contains(err.Error(), "return.conf:2:1") || !strings.Contains(err.Error(), "last directive") {
		t.Fatalf("expected included source diagnostic, got %v", err)
	}

	writeFixture(t, filepath.Join(fixture.directory, "cycle.conf"), []byte(`include cycle.conf;`))

	_, err = Compile([]byte(`include cycle.conf;`), filepath.Join(fixture.directory, "rotx.conf"))
	if err == nil || !strings.Contains(err.Error(), "include cycle") {
		t.Fatalf("expected include cycle, got %v", err)
	}

	_, err = Compile([]byte(`include absent/*.conf;`), filepath.Join(fixture.directory, "rotx.conf"))
	if err == nil || !strings.Contains(err.Error(), "matched no files") {
		t.Fatalf("expected missing include, got %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	fixture := newIdentityFixture(t)
	cases := []invalidConfigCase{
		{name: "empty", text: "", want: "one top-level"},
		{name: "no servers", text: `http {}`, want: "at least one server"},
		{name: "two http", text: `http {} http {}`, want: "one top-level"},
		{name: "missing keys", text: `http { server {} }`, want: "requires name"},
		{name: "unknown", text: fixture.config(`mystery yes;`), want: "unknown or misplaced"},
		{name: "server return", text: fixture.config(`return 200;`), want: "misplaced"},
		{name: "server proxy", text: fixture.config(`proxy_pass http://localhost;`), want: "misplaced"},
		{name: "nested", text: fixture.config(`location / { location /x {} }`), want: "nested blocks"},
		{name: "arguments", text: fixture.config(`cache on off;`), want: "argument count"},
		{name: "singleton", text: fixture.config(`cache on; cache off;`), want: "first declared at"},
		{name: "handlers", text: fixture.config(`location / { root files; return 200; }`), want: "conflicts"},
		{name: "return last", text: fixture.config(`location / { return 200; cache on; }`), want: "last directive"},
		{name: "regex quoting", text: fixture.config(`location ~ ^/foo {} `), want: "must be quoted"},
		{name: "regex syntax", text: fixture.config(`location ~ "[" {} `), want: "invalid regular expression"},
		{name: "regex alias", text: fixture.config(`location ~ "foo" { alias files; }`), want: "alias is not supported"},
		{name: "prefix duplicate", text: fixture.config(`location /foo {} location ^~ /foo {}`), want: "duplicate prefix"},
		{name: "exact duplicate", text: fixture.config(`location = /foo {} location = /f%6Fo {}`), want: "duplicate exact"},
		{name: "index traversal", text: fixture.config(`index ../secret;`), want: "local filename"},
		{name: "index missing", text: fixture.config(`index;`), want: "argument count"},
		{name: "cache zero", text: fixture.config(`cache 0s;`), want: "invalid or overflows"},
		{name: "cache compound", text: fixture.config(`cache 1h30m;`), want: "positive integer"},
		{name: "cache sign", text: fixture.config(`cache +1s;`), want: "positive integer"},
		{name: "cache overflow", text: fixture.config(`cache 9223372036854775807d;`), want: "overflows"},
		{name: "buffer without proxy", text: fixture.config(`location / { proxy_buffer on; }`), want: "requires proxy_pass"},
		{name: "path without proxy", text: fixture.config(`location / { proxy_path /x; }`), want: "requires proxy_pass"},
		{name: "proxy query", text: fixture.config(`location / { proxy_pass http://localhost/?x; }`), want: "without credentials"},
		{name: "proxy fragment", text: fixture.config(`location / { proxy_pass "http://localhost/#"; }`), want: "without credentials"},
		{name: "proxy port", text: fixture.config(`location / { proxy_pass http://localhost:99999; }`), want: "port"},
		{name: "header name", text: fixture.config(`header_set "bad name" value;`), want: "invalid header name"},
		{name: "header newline", text: fixture.config(`header_set X "bad\nvalue";`), want: "control character"},
		{name: "transport header", text: fixture.config(`header_unset content-length;`), want: "HTTP transport"},
		{name: "bodyless status", text: fixture.config(`location / { return 204 "body"; }`), want: "cannot have a response body"},
		{name: "interim status", text: fixture.config(`location / { return 103; }`), want: "final HTTP status"},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile([]byte(test.text), filepath.Join(fixture.directory, "rotx.conf"))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("want %q, got %v", test.want, err)
			}
		})
	}

	duplicated := strings.Replace(fixture.config(""), "} }", fmt.Sprintf(`} server { name %s; key_private private.pem; key_public public.pem; } }`, fixture.name), 1)

	_, err := Compile([]byte(duplicated), filepath.Join(fixture.directory, "rotx.conf"))
	if err == nil || !strings.Contains(err.Error(), "duplicate onion identity") {
		t.Fatalf("duplicate identity: %v", err)
	}
}

func TestIdentityFormatsAndMatching(t *testing.T) {
	fixture := newIdentityFixture(t)
	compileFixture(t, fixture, fixture.config(""))
	expanded := sha512.Sum512(fixture.private.Seed())
	expanded[0] &= 248
	expanded[31] &= 63
	expanded[31] |= 64
	writeFixture(t, filepath.Join(fixture.directory, "private.pem"), append([]byte(torPrivateHeader), expanded[:]...))
	writeFixture(t, filepath.Join(fixture.directory, "public.pem"), append([]byte(torPublicHeader), fixture.public...))
	compileFixture(t, fixture, fixture.config(""))

	expanded[8] ^= 1
	writeFixture(t, filepath.Join(fixture.directory, "private.pem"), append([]byte(torPrivateHeader), expanded[:]...))

	_, err := Compile([]byte(fixture.config("")), filepath.Join(fixture.directory, "rotx.conf"))
	if err == nil || !strings.Contains(err.Error(), "key_private does not match") {
		t.Fatalf("expected private mismatch, got %v", err)
	}

	writeFixture(t, filepath.Join(fixture.directory, "public.pem"), fixture.public)

	_, err = Compile([]byte(fixture.config("")), filepath.Join(fixture.directory, "rotx.conf"))
	if err == nil || !strings.Contains(err.Error(), "expected Tor native") {
		t.Fatalf("bare keys must fail: %v", err)
	}

	invalidNames := []string{strings.ToUpper(fixture.name), fixture.name + ".onion", strings.Repeat("a", 56)}

	for _, name := range invalidNames {
		_, err := onionPublicKey(name)
		if err == nil {
			t.Fatalf("invalid name accepted: %s", name)
		}
	}
}

func TestCompiledOwnershipAndConcurrentLookup(t *testing.T) {
	fixture := newIdentityFixture(t)
	source := []byte(fixture.config(`location /prefix { return 200 "owned"; }`))

	compiled, err := Compile(source, filepath.Join(fixture.directory, "rotx.conf"))
	if err != nil {
		t.Fatal(err)
	}

	clear(source)

	var workers sync.WaitGroup

	for range 16 {
		workers.Go(func() {
			for range 100 {
				route := compiled.Match(fixture.name, "/prefix/file")
				if route.Body() != "owned" {
					t.Error("compiled data was mutated")
				}
			}
		})
	}

	workers.Wait()

	allocations := testing.AllocsPerRun(100, func() {
		compiled.Match(fixture.name, "/prefix/file")
	})

	if allocations != 0 {
		t.Fatalf("prefix lookup allocates: %v", allocations)
	}
}

func BenchmarkCompiledMatch(b *testing.B) {
	fixture := newIdentityFixture(b)

	var locations strings.Builder

	locations.Grow(50000)

	for index := range 1000 {
		fmt.Fprintf(&locations, "location /route/%d { return 200; }\n", index)
	}

	compiled := compileFixture(b, fixture, fixture.config(locations.String()))
	b.ReportAllocs()

	for b.Loop() {
		compiled.Match(fixture.name, "/route/789/file")
	}
}

func newIdentityFixture(t testing.TB) identityFixture {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	checksumInput := append([]byte(".onion checksum"), public...)
	checksumInput = append(checksumInput, 3)
	checksum := sha3.Sum256(checksumInput)
	address := append([]byte(nil), public...)
	address = append(address, checksum[:2]...)
	address = append(address, 3)
	name := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(address))
	directory := t.TempDir()

	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}

	writeFixture(t, filepath.Join(directory, "private.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
	writeFixture(t, filepath.Join(directory, "public.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))

	return identityFixture{name: name, directory: directory, private: private, public: public}
}

func compileFixture(t testing.TB, fixture identityFixture, text string) *Config {
	t.Helper()

	compiled, err := Compile([]byte(text), filepath.Join(fixture.directory, "rotx.conf"))
	if err != nil {
		t.Fatal(err)
	}

	return compiled
}

func writeFixture(t testing.TB, filename string, contents []byte) {
	t.Helper()

	err := os.WriteFile(filename, contents, 0600)
	if err != nil {
		t.Fatal(err)
	}
}
