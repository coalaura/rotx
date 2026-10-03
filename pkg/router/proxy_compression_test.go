package router

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type proxyCompressionCase struct {
	name       string
	header     string
	value      string
	status     int
	enabled    bool
	compressed bool
}

func TestProxyCompression(t *testing.T) {
	modes := []string{"off", "on"}
	encodings := []string{"gzip", "zstd", "br"}

	cases := []proxyCompressionCase{
		{name: "enabled", status: 200, enabled: true, compressed: true},
		{name: "disabled", status: 200},
		{name: "already encoded", header: "Content-Encoding", value: "custom", status: 200, enabled: true},
		{name: "no transform", header: "Cache-Control", value: "public, no-transform", status: 200, enabled: true},
		{name: "event stream", header: "Content-Type", value: "text/event-stream; charset=utf-8", status: 200, enabled: true},
		{name: "partial", header: "Content-Range", value: "bytes 0-3/9", status: 206, enabled: true},
		{name: "no content", status: 204, enabled: true},
	}

	for _, mode := range modes {
		for _, encoding := range encodings {
			for _, test := range cases {
				t.Run(mode+"/"+encoding+"/"+test.name, func(t *testing.T) {
					enabled := "off"

					if test.enabled {
						enabled = "on"
					}

					settings := fmt.Sprintf(`compress zstd gzip brotli; location / { proxy_pass http://upstream; proxy_compress %s; proxy_buffer %s; }`, enabled, mode)

					compiled, host := routerConfig(t, settings)

					router := New(compiled, Handoffs{})

					router.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
						headers := make(http.Header)

						headers.Set("Content-Length", "13")
						headers.Set("Etag", `"original"`)
						headers.Set("Digest", "original digest")
						headers.Set("Content-Type", "text/plain")

						if test.header != "" {
							headers.Set(test.header, test.value)
						}

						trailers := http.Header{"Digest": {"original trailer"}, "X-End": {"complete"}}

						return &http.Response{StatusCode: test.status, Header: headers, Body: io.NopCloser(strings.NewReader("upstream body")), Trailer: trailers}, nil
					})

					request := httptest.NewRequest("GET", "http://"+host+"/", nil)

					request.Header.Set("Accept-Encoding", encoding)

					recorder := httptest.NewRecorder()

					router.ServeHTTP(recorder, request)

					if test.compressed {
						if recorder.Header().Get("Content-Encoding") != encoding || decodeBody(t, encoding, recorder.Body.Bytes()) != "upstream body" {
							t.Fatalf("invalid compressed proxy response: %v", recorder.Header())
						}

						if recorder.Header().Get("Content-Length") != "" || recorder.Header().Get("Digest") != "" || recorder.Header().Get("Etag") != `W/"original"` {
							t.Fatal("transformed response retained original representation metadata")
						}

						result := recorder.Result()
						defer result.Body.Close()

						if result.Trailer.Get("Digest") != "" || result.Trailer.Get("X-End") != "complete" {
							t.Fatalf("incorrect transformed trailers: %v", result.Trailer)
						}
					} else if test.status != 204 && recorder.Body.String() != "upstream body" {
						t.Fatal("bypass changed upstream body")
					}
				})
			}
		}
	}
}

func TestProxyCompressionBuffering(t *testing.T) {
	modes := []string{"off", "on"}

	for _, mode := range modes {
		compiled, host := routerConfig(t, fmt.Sprintf(`compress gzip; location / { proxy_pass http://upstream; proxy_compress on; proxy_buffer %s; }`, mode))

		recorder := httptest.NewRecorder()

		router := New(compiled, Handoffs{Proxy: func(response *Response, request *http.Request, target url.URL) error {
			_, err := response.Write([]byte("first chunk"))
			if err != nil {
				return err
			}

			err = response.FlushError()
			if err != nil {
				return err
			}

			if mode == "on" && (recorder.Body.Len() != 0 || response.encoder != nil || response.body.String() != "first chunk") {
				t.Fatal("buffered proxy encoded or published before body completion")
			}

			if mode == "off" && (recorder.Body.Len() == 0 || response.encoder == nil) {
				t.Fatal("streaming encoder failed to flush")
			}

			return nil
		}})

		request := httptest.NewRequest("GET", "http://"+host+"/", nil)

		request.Header.Set("Accept-Encoding", "gzip")

		router.ServeHTTP(recorder, request)

		if decodeBody(t, "gzip", recorder.Body.Bytes()) != "first chunk" {
			t.Fatal("invalid final compressed stream")
		}
	}
}

func TestServerTokens(t *testing.T) {
	policies := []string{"auto", "off", "full", "keep"}
	expected := []string{"rotx", "", "rotx/v1.2.3", "upstream"}

	for index, policy := range policies {
		settings := fmt.Sprintf(`server_tokens %s; location / { proxy_pass http://upstream; } location /custom { proxy_pass http://upstream; header_set Server custom; } location /unset { proxy_pass http://upstream; header_unset Server; } location /error { proxy_pass http://upstream; }`, policy)

		compiled, host := routerConfig(t, settings)

		router := New(compiled, Handoffs{Version: "1.2.3", Proxy: func(response *Response, request *http.Request, target url.URL) error {
			if request.URL.Path == "/error" {
				return io.ErrUnexpectedEOF
			}

			response.Header().Set("Server", "upstream")
			response.WriteHeader(200)

			return nil
		}})

		paths := []string{"/", "/custom", "/unset", "/error"}
		wanted := []string{expected[index], "custom", "", expected[index]}

		if policy == "keep" {
			wanted[3] = ""
		}

		for offset, path := range paths {
			request := httptest.NewRequest("GET", "http://"+host+path, nil)

			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, request)

			if recorder.Header().Get("Server") != wanted[offset] {
				t.Fatalf("%s %s: got %q, want %q", policy, path, recorder.Header().Get("Server"), wanted[offset])
			}
		}
	}
}
