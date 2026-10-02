package router

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStaticServing(t *testing.T) {
	directory := t.TempDir()

	writeFixture(t, directory, "hello.txt", "hello world")
	writeFixture(t, directory, "docs/home.html", "<h1>index</h1>")
	writeFixture(t, directory, "empty/.keep", "")

	settings := fmt.Sprintf(`
		root %q;
		index missing.html home.html;
		cache on;
		header_set X-Static yes;
		location /assets/ { alias %q; }
		location = /single { alias %q; }
		location = /directory { alias %q; }
		location /uncached/ { alias %q; cache auto; }
		location /private/ { alias %q; cache off; }
	`, filepath.ToSlash(directory), filepath.ToSlash(directory), filepath.ToSlash(filepath.Join(directory, "hello.txt")), filepath.ToSlash(filepath.Join(directory, "docs")), filepath.ToSlash(directory), filepath.ToSlash(directory))

	compiled, host := routerConfig(t, settings)

	router := New(compiled, Handoffs{})
	t.Cleanup(router.CloseIdleConnections)

	cases := []requestCase{
		{path: "/hello.txt", body: "hello world", status: 200},
		{path: "/assets/hello.txt", body: "hello world", status: 200},
		{path: "/single", body: "hello world", status: 200},
		{path: "/directory", body: "<h1>index</h1>", status: 200},
		{path: "/docs/", body: "<h1>index</h1>", status: 200},
		{path: "/empty/", body: "Not Found\n", status: 404},
		{path: "/missing", body: "Not Found\n", status: 404},
		{path: "/hello.txt/", body: "Not Found\n", status: 404},
	}

	for _, test := range cases {
		request := httptest.NewRequest(http.MethodGet, "http://"+host+test.path, nil)

		recorder := httptest.NewRecorder()

		err := router.Handle(recorder, request)

		if err != nil || recorder.Code != test.status || recorder.Body.String() != test.body {
			t.Fatalf("%s: status=%d body=%q error=%v", test.path, recorder.Code, recorder.Body.String(), err)
		}

		if recorder.Header().Get("X-Static") != "yes" {
			t.Fatal("static response skipped header policy")
		}
	}

	request := httptest.NewRequest(http.MethodGet, "http://"+host+"/docs?q=1", nil)

	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != 301 || recorder.Header().Get("Location") != "/docs/?q=1" {
		t.Fatalf("directory redirect: %d %q", recorder.Code, recorder.Header().Get("Location"))
	}

	request = httptest.NewRequest(http.MethodHead, "http://"+host+"/hello.txt", nil)

	recorder = httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != 200 || recorder.Body.Len() != 0 || recorder.Header().Get("Content-Length") != "11" {
		t.Fatal("incorrect static HEAD")
	}

	tag := recorder.Header().Get("Etag")
	modified := recorder.Header().Get("Last-Modified")

	if tag == "" || modified == "" || recorder.Header().Get("Cache-Control") != "public, max-age=3600" {
		t.Fatal("missing static cache metadata")
	}

	request = httptest.NewRequest(http.MethodGet, "http://"+host+"/hello.txt", nil)

	request.Header.Set("If-None-Match", tag)

	recorder = httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != 304 || recorder.Body.Len() != 0 || recorder.Header().Get("Etag") != tag {
		t.Fatal("static conditional request failed")
	}

	request.Header.Set("If-None-Match", "")
	request.Header.Set("If-Modified-Since", modified)

	recorder = httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != 200 || recorder.Body.String() != "hello world" {
		t.Fatal("empty If-None-Match did not take precedence")
	}

	request.Header["If-None-Match"] = []string{`"other"`, tag}
	request.Header.Set("Range", "bytes=1-4")

	recorder = httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != 304 || recorder.Body.Len() != 0 {
		t.Fatal("repeated If-None-Match did not take precedence over range")
	}

	request.Header.Del("If-None-Match")
	request.Header.Del("If-Modified-Since")
	request.Header.Set("Range", "bytes=1-4")

	recorder = httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != 206 || recorder.Body.String() != "ello" || recorder.Header().Get("Content-Range") != "bytes 1-4/11" || recorder.Header().Get("Etag") != tag {
		t.Fatalf("static range failed: %d %q %#v", recorder.Code, recorder.Body.String(), recorder.Header())
	}

	request.Header.Set("Range", "bytes=100-200")

	recorder = httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != 416 || recorder.Header().Get("Content-Range") != "bytes */11" {
		t.Fatal("unsatisfiable range failed")
	}

	paths := []string{"/uncached/hello.txt", "/private/hello.txt"}

	for _, path := range paths {
		request = httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)

		recorder = httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		if recorder.Header().Get("Etag") != "" || recorder.Header().Get("Last-Modified") != "" {
			t.Fatal("disabled static cache generated validators")
		}

		if strings.HasPrefix(path, "/private/") && recorder.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cache off failed")
		}
	}

	request = httptest.NewRequest(http.MethodPost, "http://"+host+"/hello.txt", strings.NewReader("body"))

	recorder = httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != 405 || recorder.Header().Get("Allow") != "GET, HEAD" {
		t.Fatal("static method rejection failed")
	}
}

func TestStaticContainment(t *testing.T) {
	directory := t.TempDir()

	writeFixture(t, directory, "public/inside.txt", "inside")
	writeFixture(t, directory, "secret.txt", "secret")
	writeFixture(t, directory, "public/sub/.keep", "")

	err := os.Symlink("../secret.txt", filepath.Join(directory, "public", "escape.txt"))
	if err != nil {
		t.Fatal(err)
	}

	err = os.Symlink("../inside.txt", filepath.Join(directory, "public", "sub", "index.html"))
	if err != nil {
		t.Fatal(err)
	}

	settings := fmt.Sprintf(`root %q; location = /exact { alias %q; }`, filepath.ToSlash(filepath.Join(directory, "public")), filepath.ToSlash(filepath.Join(directory, "public", "sub")))

	compiled, host := routerConfig(t, settings)

	router := New(compiled, Handoffs{})
	t.Cleanup(router.CloseIdleConnections)

	cases := []requestCase{
		{path: "/escape.txt", body: "Not Found\n", status: 404},
		{path: "/../secret.txt", body: "Not Found\n", status: 404},
		{path: "/%2e%2e/secret.txt", body: "Not Found\n", status: 404},
		{path: "/%252e%252e/secret.txt", body: "Not Found\n", status: 404},
		{path: "/sub/", body: "inside", status: 200},
		{path: "/exact", body: "Not Found\n", status: 404},
	}

	for _, test := range cases {
		request := httptest.NewRequest(http.MethodGet, "http://"+host+test.path, nil)

		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		if recorder.Code != test.status || recorder.Body.String() != test.body {
			t.Fatalf("containment %s: %d %q", test.path, recorder.Code, recorder.Body.String())
		}
	}
}

func writeFixture(t *testing.T, directory, name, content string) {
	t.Helper()

	filename := filepath.Join(directory, filepath.FromSlash(name))

	err := os.MkdirAll(filepath.Dir(filename), 0700)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filename, []byte(content), 0600)
	if err != nil {
		t.Fatal(err)
	}
}
