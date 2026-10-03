package router

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coalaura/rotx/pkg/config"
)

type conditionalCase struct {
	name   string
	method string
	match  string
	since  string
	status int
}

type requestCase struct {
	path   string
	body   string
	status int
}

type failingWriter struct {
	headers http.Header
	err     error
}

func (w *failingWriter) Header() http.Header {
	return w.headers
}

func (w *failingWriter) WriteHeader(status int) {
}

func (w *failingWriter) Write(body []byte) (int, error) {
	return 0, w.err
}

func TestReturnAndNormalizedRouting(t *testing.T) {
	compiled, host := routerConfig(t, `
		header_set Example one;
		location = /hello/world { header_set example two; header_add EXAMPLE three; return 200 "hello"; }
		location = /%252e%252e/file { return 200 "literal percent"; }
		location = /empty { return 204; }
	`)

	router := New(compiled, Handoffs{})

	cases := []requestCase{
		{path: "/hello//unused/../w%6Frld?q=ignored", body: "hello", status: 200},
		{path: "/%252e%252e/file", body: "literal percent", status: 200},
		{path: "/empty", body: "", status: 204},
		{path: "/missing", body: "Not Found\n", status: 404},
	}

	for _, test := range cases {
		request := httptest.NewRequest(http.MethodGet, "http://"+host+test.path, nil)

		original := request.URL.Path

		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		if recorder.Code != test.status || recorder.Body.String() != test.body || request.URL.Path != original {
			t.Fatalf("%s: status %d body %q request path %q", test.path, recorder.Code, recorder.Body.String(), request.URL.Path)
		}

		if test.body == "hello" && strings.Join(recorder.Header().Values("Example"), ",") != "two,three" {
			t.Fatalf("ordered header operations failed: %#v", recorder.Header())
		}
	}

	request := httptest.NewRequest(http.MethodHead, "http://"+strings.ToUpper(host)+":80/hello/world", nil)

	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != 200 || recorder.Body.Len() != 0 || recorder.Header().Get("Content-Length") != "5" {
		t.Fatal("HEAD or case insensitive host matching failed")
	}

	request.Host = "unknown.onion"

	recorder = httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != 404 {
		t.Fatal("unknown hosts must not fall back to the first server")
	}
}

func TestProxyBufferingAndHeaderCommit(t *testing.T) {
	modes := []string{"off", "on"}

	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			compiled, host := routerConfig(t, fmt.Sprintf(`location / { proxy_pass http://localhost/base; proxy_buffer %s; cache 1h; header_unset Removed; header_set X-Final final; }`, mode))

			recorder := httptest.NewRecorder()

			handoffs := Handoffs{Proxy: func(response *Response, request *http.Request, target url.URL) error {
				if target.String() != "http://localhost/base/path?q=a%2Fb" {
					t.Fatalf("unexpected URL %s", target.String())
				}

				response.Header().Set("Removed", "remove")
				response.Header().Set("X-Final", "upstream")
				response.Header().Set("Etag", `"upstream"`)

				response.WriteHeader(201)

				response.Header().Set("X-Final", "too late")

				_, err := io.WriteString(response, "first")
				if err != nil {
					return err
				}

				err = http.NewResponseController(response).Flush()
				if err != nil {
					return err
				}

				if mode == "on" && (recorder.Body.Len() != 0 || len(recorder.Header()) != 0 || recorder.Flushed) {
					t.Fatal("buffered response was published before handoff returned")
				}

				if mode == "off" && (recorder.Body.String() != "first" || recorder.Code != 201 || !recorder.Flushed) {
					t.Fatal("streaming response did not publish immediately")
				}

				_, err = io.WriteString(response, "second")
				return err
			}}

			router := New(compiled, handoffs)

			request := httptest.NewRequest(http.MethodGet, "http://"+host+"/path?q=a%2Fb", nil)

			err := router.Handle(recorder, request)
			if err != nil {
				t.Fatal(err)
			}

			headers := recorder.Result().Header
			if recorder.Code != 201 || recorder.Body.String() != "firstsecond" || headers.Get("X-Final") != "final" || headers.Get("Removed") != "" || headers.Get("Cache-Control") != "public, max-age=3600" || headers.Get("Etag") != `"upstream"` || headers.Get("Last-Modified") != "" {
				t.Fatalf("incorrect committed response: %d %q %#v", recorder.Code, recorder.Body.String(), headers)
			}
		})
	}
}

func TestStaticConditionalResponses(t *testing.T) {
	compiled, host := routerConfig(t, `root .; cache on; header_set X-Final yes;`)

	modified := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)

	tag := `"content,version"`

	handoffs := Handoffs{Static: func(response *Response, request *http.Request, target StaticTarget) error {
		if filepath.Base(target.Path) != "file" || target.Route.Index(0) != "index.html" {
			t.Fatalf("unexpected static target %#v", target)
		}

		err := response.SetMetadata(Metadata{Modified: modified, Size: 4, ETag: tag})
		if err != nil {
			return err
		}

		response.Header().Set("Content-Length", "4")

		_, err = io.WriteString(response, "body")
		return err
	}}

	router := New(compiled, handoffs)

	newer := modified.Add(time.Hour).Format(http.TimeFormat)
	older := modified.Add(-time.Hour).Format(http.TimeFormat)

	cases := []conditionalCase{
		{name: "normal", method: "GET", status: 200},
		{name: "head", method: "HEAD", status: 200},
		{name: "same second", method: "GET", since: modified.Format(http.TimeFormat), status: 304},
		{name: "newer", method: "GET", since: newer, status: 304},
		{name: "older", method: "GET", since: older, status: 200},
		{name: "bad date", method: "GET", since: "invalid", status: 200},
		{name: "matching tag", method: "GET", match: tag, since: older, status: 304},
		{name: "weak list tag", method: "GET", match: `"other", W/"content,version"`, status: 304},
		{name: "wildcard", method: "HEAD", match: "*", status: 304},
		{name: "wildcard whitespace", method: "GET", match: " \t* \t", status: 304},
		{name: "tag precedence", method: "GET", match: `"other"`, since: newer, status: 200},
		{name: "post", method: "POST", match: tag, since: newer, status: 200},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "http://"+host+"/file", nil)

			if test.match != "" {
				request.Header.Set("If-None-Match", test.match)
			}

			if test.since != "" {
				request.Header.Set("If-Modified-Since", test.since)
			}

			recorder := httptest.NewRecorder()

			err := router.Handle(recorder, request)
			if err != nil {
				t.Fatal(err)
			}

			if recorder.Code != test.status || recorder.Header().Get("Etag") != tag || recorder.Header().Get("Last-Modified") != modified.Format(http.TimeFormat) || recorder.Header().Get("X-Final") != "yes" {
				t.Fatalf("unexpected response: %d %#v", recorder.Code, recorder.Header())
			}

			if test.status == 304 || test.method == "HEAD" {
				if recorder.Body.Len() != 0 {
					t.Fatal("body written for HEAD/304")
				}
			} else if recorder.Body.String() != "body" {
				t.Fatal("missing static body")
			}

			if test.status == 304 && recorder.Header().Get("Content-Length") != "" {
				t.Fatal("304 retained original content length")
			}
		})
	}
}

func TestCacheOverridesAndWeakValidator(t *testing.T) {
	compiled, host := routerConfig(t, `
		root .; cache on;
		location /auto { cache auto; }
		location /off { cache off; }
		location /override { header_unset ETag; header_unset Last-Modified; header_set Cache-Control private; header_unset Content-Type; }
	`)

	modified := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	router := New(compiled, Handoffs{Static: func(response *Response, request *http.Request, target StaticTarget) error {
		response.Header().Set("Cache-Control", "upstream")
		response.Header().Set("Content-Type", "text/plain")

		err := response.SetMetadata(Metadata{Modified: modified, Size: 4})
		if err != nil {
			return err
		}

		_, err = io.WriteString(response, "body")
		return err
	}})

	paths := []string{"/auto", "/off", "/override", "/enabled"}

	for _, path := range paths {
		request := httptest.NewRequest("GET", "http://"+host+path, nil)

		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		headers := recorder.Result().Header

		switch path {
		case "/auto":
			if headers.Get("Cache-Control") != "upstream" || headers.Get("Etag") != "" {
				t.Fatal("cache auto modified upstream caching")
			}
		case "/off":
			if headers.Get("Cache-Control") != "no-store" || headers.Get("Etag") != "" {
				t.Fatal("cache off did not disable caching")
			}
		case "/override":
			if headers.Get("Cache-Control") != "private" || headers.Get("Etag") != "" || headers.Get("Last-Modified") != "" || headers.Get("Content-Type") != "" {
				t.Fatalf("header overrides did not run last: %#v", headers)
			}
		case "/enabled":
			tag := headers.Get("Etag")
			if !strings.HasPrefix(tag, `W/"`) {
				t.Fatal("size/mtime tag must be weak")
			}

			request.Header.Set("If-None-Match", strings.TrimPrefix(tag, "W/"))

			recorder = httptest.NewRecorder()

			router.ServeHTTP(recorder, request)

			if recorder.Code != 304 {
				t.Fatal("generated weak validator failed revalidation")
			}
		}
	}
}

func TestBufferedFailure(t *testing.T) {
	compiled, host := routerConfig(t, `location / { proxy_pass http://localhost; proxy_buffer on; header_set X-Final yes; }`)

	failure := errors.New("upstream failure")

	router := New(compiled, Handoffs{Proxy: func(response *Response, request *http.Request, target url.URL) error {
		response.Header().Set("X-Leak", "bad")

		_, err := response.Write([]byte("partial upstream body"))
		if err != nil {
			return err
		}

		return failure
	}})

	request := httptest.NewRequest("GET", "http://"+host+"/", nil)

	recorder := httptest.NewRecorder()

	err := router.Handle(recorder, request)

	if !errors.Is(err, failure) || recorder.Code != 502 || recorder.Body.String() != "Bad Gateway\n" || recorder.Header().Get("X-Leak") != "" || recorder.Header().Get("X-Final") != "yes" {
		t.Fatalf("buffered failure leaked response: %v %d %q %#v", err, recorder.Code, recorder.Body.String(), recorder.Header())
	}
}

func TestHandoffWriteErrors(t *testing.T) {
	failure := errors.New("downstream disconnected")

	modes := []string{"off", "on"}

	for _, mode := range modes {
		compiled, host := routerConfig(t, fmt.Sprintf(`location / { proxy_pass http://localhost; proxy_buffer %s; }`, mode))

		router := New(compiled, Handoffs{Proxy: func(response *Response, request *http.Request, target url.URL) error {
			_, err := response.Write([]byte("body"))
			return err
		}})

		request := httptest.NewRequest("GET", "http://"+host+"/", nil)
		writer := &failingWriter{headers: make(http.Header), err: failure}

		err := router.Handle(writer, request)
		if !errors.Is(err, failure) {
			t.Fatalf("%s failed to propagate write error: %v", mode, err)
		}
	}
}

func routerConfig(t *testing.T, body string) (*config.Config, string) {
	t.Helper()

	directory := t.TempDir()

	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))

	public := private.Public().(ed25519.PublicKey)

	expanded := sha512.Sum512(private.Seed())

	expanded[0] &= 248
	expanded[31] &= 63
	expanded[31] |= 64

	checksumInput := append([]byte(".onion checksum"), public...)

	checksumInput = append(checksumInput, 3)

	checksum := sha3.Sum256(checksumInput)

	address := append([]byte(nil), public...)

	address = append(address, checksum[:2]...)
	address = append(address, 3)

	name := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(address))

	err := os.WriteFile(filepath.Join(directory, "private.key"), append([]byte("== ed25519v1-secret: type0 ==\x00\x00\x00"), expanded[:]...), 0600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(directory, "public.key"), append([]byte("== ed25519v1-public: type0 ==\x00\x00\x00"), public...), 0600)
	if err != nil {
		t.Fatal(err)
	}

	text := fmt.Sprintf(`http { server { name %s; key_private private.key; key_public public.key; %s } }`, name, body)

	compiled, err := config.Compile([]byte(text), filepath.Join(directory, "rotx.conf"))
	if err != nil {
		t.Fatal(err)
	}

	return compiled, name + ".onion"
}
