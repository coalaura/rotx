package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

type upstreamRequest struct {
	method  string
	host    string
	uri     string
	body    string
	headers http.Header
}

type interruptedBody struct {
	read bool
}

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func (body *interruptedBody) Read(destination []byte) (int, error) {
	if body.read {
		return 0, io.ErrUnexpectedEOF
	}

	body.read = true

	return copy(destination, "partial"), nil
}

func (body *interruptedBody) Close() error {
	return nil
}

func TestProxyHTTP(t *testing.T) {
	received := make(chan upstreamRequest, 4)

	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)

			return
		}

		received <- upstreamRequest{headers: request.Header.Clone(), method: request.Method, host: request.Host, uri: request.RequestURI, body: string(body)}

		writer.Header().Set("Connection", "X-Remove")
		writer.Header().Set("X-Remove", "hidden")
		writer.Header().Set("X-Policy", "upstream")
		writer.Header().Add("Set-Cookie", "one=1")
		writer.Header().Add("Set-Cookie", "two=2")
		writer.Header().Set("Trailer", "X-Checksum, X-Policy")
		writer.Header().Set("Location", "/not-followed")

		writer.WriteHeader(http.StatusTemporaryRedirect)

		_, err = io.WriteString(writer, "upstream body")
		if err != nil {
			t.Error(err)
		}

		writer.Header().Set("X-Checksum", "complete")
		writer.Header().Set("X-Policy", "trailer must not override config")
	}))

	t.Cleanup(upstream.Close)

	modes := []string{"off", "on"}

	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			settings := fmt.Sprintf(`location / { proxy_pass %s/base; proxy_buffer %s; cache off; header_set X-Policy configured; } location = /fixed { proxy_pass %s/base; proxy_path /replacement; }`, upstream.URL, mode, upstream.URL)

			compiled, host := routerConfig(t, settings)

			router := New(compiled, Handoffs{})
			t.Cleanup(router.CloseIdleConnections)

			request := httptest.NewRequest(http.MethodPost, "http://"+host+"/some//path?q=%2F&x=1", strings.NewReader("request body"))

			request.Header.Set("Connection", "X-Hop")
			request.Header.Set("X-Hop", "hidden")
			request.Header.Set("Forwarded", "for=spoofed")
			request.Header.Set("X-Forwarded-For", "spoofed")
			request.Header.Set("X-Real-Ip", "spoofed")
			request.Header.Set("X-Forwarded-Host", "spoofed")
			request.Header.Set("X-Forwarded-Proto", "spoofed")
			request.Header.Set("Authorization", "Bearer token")

			recorder := httptest.NewRecorder()

			err := router.Handle(recorder, request)
			if err != nil {
				t.Fatal(err)
			}

			seen := <-received
			if seen.method != "POST" || seen.uri != "/base/some/path?q=%2F&x=1" || seen.body != "request body" || seen.host != strings.TrimPrefix(upstream.URL, "http://") {
				t.Fatalf("unexpected outgoing request: %#v", seen)
			}

			removed := []string{"Connection", "X-Hop", "Forwarded", "X-Forwarded-For", "X-Real-Ip", "Accept-Encoding", "User-Agent"}

			for _, name := range removed {
				if seen.headers.Get(name) != "" {
					t.Fatalf("unexpected outgoing %s: %q", name, seen.headers.Get(name))
				}
			}

			if seen.headers.Get("X-Forwarded-Host") != host || seen.headers.Get("X-Forwarded-Proto") != "http" || seen.headers.Get("Authorization") != "Bearer token" {
				t.Fatalf("incorrect forwarded headers: %#v", seen.headers)
			}

			if request.URL.Path != "/some//path" || request.Header.Get("X-Hop") != "hidden" || request.Header.Get("X-Forwarded-Host") != "spoofed" {
				t.Fatal("proxy mutated caller request")
			}

			result := recorder.Result()
			defer result.Body.Close()

			if result.StatusCode != 307 || recorder.Body.String() != "upstream body" || result.Header.Get("Location") != "/not-followed" || len(result.Header.Values("Set-Cookie")) != 2 {
				t.Fatalf("unexpected proxy response: %d %q %#v", result.StatusCode, recorder.Body.String(), result.Header)
			}

			if result.Header.Get("X-Remove") != "" || result.Header.Get("Connection") != "" || result.Header.Get("X-Policy") != "configured" || result.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("incorrect response policy: %#v", result.Header)
			}

			if result.Trailer.Get("X-Checksum") != "complete" || result.Trailer.Get("X-Policy") != "" {
				t.Fatalf("incorrect trailers: %#v", result.Trailer)
			}

			request = httptest.NewRequest(http.MethodGet, "http://"+host+"/fixed?q=kept", nil)

			recorder = httptest.NewRecorder()

			err = router.Handle(recorder, request)
			if err != nil {
				t.Fatal(err)
			}

			seen = <-received
			if seen.uri != "/replacement?q=kept" {
				t.Fatalf("fixed proxy path: %s", seen.uri)
			}
		})
	}
}

func TestProxyTLSAndCancellation(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Encoding", "gzip")
		writer.Header().Set("Content-Length", "4")

		writer.WriteHeader(http.StatusOK)

		writer.Write([]byte{1, 2, 3, 4})
	}))

	t.Cleanup(upstream.Close)

	compiled, host := routerConfig(t, fmt.Sprintf(`location / { proxy_pass %s; }`, upstream.URL))

	transport := upstream.Client().Transport.(*http.Transport).Clone()

	transport.DisableCompression = true

	router := New(compiled, Handoffs{Transport: transport})
	t.Cleanup(router.CloseIdleConnections)

	request := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)

	recorder := httptest.NewRecorder()
	err := router.Handle(recorder, request)

	if err != nil || recorder.Body.Len() != 4 || recorder.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("TLS/encoded response: %v %#v", err, recorder.Header())
	}

	ctx, cancel := context.WithCancel(request.Context())
	cancel()

	request = request.WithContext(ctx)

	recorder = httptest.NewRecorder()

	err = router.Handle(recorder, request)

	if !errors.Is(err, context.Canceled) || recorder.Code != 502 {
		t.Fatalf("cancellation: %v status %d", err, recorder.Code)
	}
}

func TestProxyInterruptedResponse(t *testing.T) {
	modes := []string{"off", "on"}

	for _, mode := range modes {
		compiled, host := routerConfig(t, fmt.Sprintf(`location / { proxy_pass http://upstream.invalid; proxy_buffer %s; header_set X-Policy yes; }`, mode))

		transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &interruptedBody{}}, nil
		})

		router := New(compiled, Handoffs{Transport: transport})

		request := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)

		recorder := httptest.NewRecorder()

		err := router.Handle(recorder, request)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("missing read failure: %v", err)
		}

		if mode == "on" && (recorder.Code != 502 || recorder.Body.String() != "Bad Gateway\n" || recorder.Flushed) {
			t.Fatal("buffered failure leaked partial response")
		}

		if mode == "off" && (recorder.Code != 200 || recorder.Body.String() != "partial" || !recorder.Flushed) {
			t.Fatal("streaming response was buffered")
		}

		if recorder.Header().Get("X-Policy") != "yes" {
			t.Fatal("error response skipped policy")
		}
	}
}

func TestProxyWireTrailers(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, err := io.Copy(io.Discard, request.Body)
		if err != nil {
			t.Error(err)

			return
		}

		writer.Header().Set("X-Uploaded", request.Trailer.Get("X-Upload"))
		writer.Header().Set("X-Spoofed", request.Trailer.Get("Forwarded"))
		writer.Header().Set("Trailer", "X-Download")

		writer.Write([]byte("download"))

		writer.Header().Set("X-Download", "checksum")
	}))

	t.Cleanup(upstream.Close)

	modes := []string{"off", "on"}

	for _, mode := range modes {
		compiled, host := routerConfig(t, fmt.Sprintf(`location / { proxy_pass %s; proxy_buffer %s; }`, upstream.URL, mode))

		router := New(compiled, Handoffs{})
		t.Cleanup(router.CloseIdleConnections)

		downstream := httptest.NewServer(router)
		t.Cleanup(downstream.Close)

		request, err := http.NewRequest(http.MethodPost, downstream.URL+"/", strings.NewReader("upload"))
		if err != nil {
			t.Fatal(err)
		}

		request.Host = host
		request.ContentLength = -1
		request.Trailer = http.Header{"X-Upload": {"checksum"}, "Forwarded": {"for=spoofed"}}

		result, err := downstream.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}

		body, err := io.ReadAll(result.Body)

		result.Body.Close()

		if err != nil || string(body) != "download" || result.Header.Get("X-Uploaded") != "checksum" || result.Header.Get("X-Spoofed") != "" || result.Trailer.Get("X-Download") != "checksum" {
			t.Fatalf("%s wire trailers: error=%v body=%q headers=%#v trailers=%#v", mode, err, body, result.Header, result.Trailer)
		}
	}
}

func TestProxyAbortsTruncatedStream(t *testing.T) {
	compiled, host := routerConfig(t, `location / { proxy_pass http://upstream.invalid; }`)

	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &interruptedBody{}}, nil
	})

	reported := make(chan error, 1)

	router := New(compiled, Handoffs{Transport: transport, Error: func(request *http.Request, err error) {
		reported <- err
	}})

	downstream := httptest.NewServer(router)
	t.Cleanup(downstream.Close)

	request, err := http.NewRequest(http.MethodGet, downstream.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}

	request.Host = host

	result, err := downstream.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}

	defer result.Body.Close()

	body, err := io.ReadAll(result.Body)
	if !errors.Is(err, io.ErrUnexpectedEOF) || string(body) != "partial" {
		t.Fatalf("truncated stream appeared successful: %v %q", err, body)
	}

	err = <-reported
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("missing stream failure report: %v", err)
	}
}
