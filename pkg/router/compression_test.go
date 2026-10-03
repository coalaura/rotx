package router

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/coalaura/rotx/pkg/config"
	"github.com/klauspost/compress/zstd"
)

type negotiationCase struct {
	value      string
	want       config.Encoding
	acceptable bool
}

func TestEncodingNegotiation(t *testing.T) {
	policy := config.CompressionPolicy{Algorithms: [3]config.Encoding{config.Zstd, config.Gzip, config.Brotli}, Count: 3}

	cases := []negotiationCase{
		{value: "", want: config.IdentityEncoding, acceptable: true},
		{value: "gzip, zstd, br", want: config.Zstd, acceptable: true},
		{value: "br;q=0.9, gzip;q=0.8, zstd;q=0.1", want: config.Brotli, acceptable: true},
		{value: "*;q=0.5, zstd;q=0", want: config.Gzip, acceptable: true},
		{value: "gzip;q=0, gzip;q=1, *;q=0", acceptable: false},
		{value: "identity;q=0, unknown", acceptable: false},
		{value: "gzip;q=0.1, identity;q=0.9", want: config.IdentityEncoding, acceptable: true},
		{value: "gzip;q=0, *;q=0, identity;q=1", want: config.IdentityEncoding, acceptable: true},
		{value: "GZIP;Q=1.000", want: config.Gzip, acceptable: true},
		{value: "gzip;q=1.001, br;q=0.2", want: config.Brotli, acceptable: true},
		{value: "gzip;q=0.1234", want: config.IdentityEncoding, acceptable: true},
	}

	for _, test := range cases {
		encoding, acceptable := negotiateEncoding([]string{test.value}, policy)
		if encoding != test.want || acceptable != test.acceptable {
			t.Fatalf("%q: got %s/%t, want %s/%t", test.value, encoding, acceptable, test.want, test.acceptable)
		}
	}

	values := []string{"gzip;q=0.5", "zstd;q=0.8, br;q=0.8"}

	allocations := testing.AllocsPerRun(100, func() {
		negotiateEncoding(values, policy)
	})

	if allocations != 0 {
		t.Fatalf("negotiation allocated %g times", allocations)
	}
}

func TestStaticCompression(t *testing.T) {
	directory := t.TempDir()

	body := strings.Repeat("compressible content\n", 1000)

	writeFixture(t, directory, "content.txt", body)

	modes := []string{"off", "memory", "file"}
	encodings := []string{"gzip", "zstd", "br"}

	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			compiled, host := routerConfig(t, fmt.Sprintf(`root %q; compress zstd gzip brotli; compress_cache %s; cache on;`, filepath.ToSlash(directory), mode))

			router := New(compiled, Handoffs{})

			router.compression.directory = t.TempDir()

			for _, encoding := range encodings {
				request := httptest.NewRequest("GET", "http://"+host+"/content.txt", nil)

				request.Header.Set("Accept-Encoding", encoding)

				full := httptest.NewRecorder()

				router.ServeHTTP(full, request)

				if full.Code != 200 || full.Header().Get("Content-Encoding") != encoding || decodeBody(t, encoding, full.Body.Bytes()) != body {
					t.Fatalf("invalid %s response: %d %v", encoding, full.Code, full.Header())
				}

				if full.Header().Get("Content-Length") != strconv.Itoa(full.Body.Len()) || !strings.HasPrefix(full.Header().Get("Content-Type"), "text/plain") || full.Header().Get("Vary") != "Accept-Encoding" {
					t.Fatalf("invalid representation metadata: %v", full.Header())
				}

				request.Method = "HEAD"

				head := httptest.NewRecorder()

				router.ServeHTTP(head, request)

				if head.Body.Len() != 0 || head.Header().Get("Content-Length") != full.Header().Get("Content-Length") || head.Header().Get("Etag") != full.Header().Get("Etag") {
					t.Fatal("HEAD disagrees with GET")
				}

				request.Method = "GET"
				request.Header.Set("If-None-Match", full.Header().Get("Etag"))

				conditional := httptest.NewRecorder()

				router.ServeHTTP(conditional, request)

				if conditional.Code != 304 || conditional.Body.Len() != 0 {
					t.Fatal("conditional compressed response failed")
				}

				request.Header.Del("If-None-Match")
				request.Header.Set("Range", "bytes=1-8")
				request.Header.Set("If-Range", full.Header().Get("Etag"))

				partial := httptest.NewRecorder()

				router.ServeHTTP(partial, request)

				if partial.Code != 206 || !bytes.Equal(partial.Body.Bytes(), full.Body.Bytes()[1:9]) || partial.Header().Get("Content-Length") != "8" {
					t.Fatalf("encoded byte range failed: %d %v", partial.Code, partial.Header())
				}

				request.Header.Set("Range", "bytes=0-2,5-8")

				multiple := httptest.NewRecorder()

				router.ServeHTTP(multiple, request)

				if multiple.Code != 200 || decodeBody(t, encoding, multiple.Body.Bytes()) != body {
					t.Fatal("multiple ranges must fall back to the complete encoded representation")
				}

				request.Header.Set("Range", "bytes=999999-")

				invalid := httptest.NewRecorder()

				router.ServeHTTP(invalid, request)

				if invalid.Code != 416 || invalid.Header().Get("Content-Encoding") != "" {
					t.Fatal("range error retained encoding")
				}
			}
		})
	}
}

func TestCompressionCompanionsAndBoundaries(t *testing.T) {
	directory := t.TempDir()

	writeFixture(t, directory, "file.txt", "source")
	writeFixture(t, directory, "file.txt.gz", string(encodeBody(t, config.Gzip, "companion")))
	writeFixture(t, directory, "file.txt.zstd", string(encodeBody(t, config.Zstd, "zstd companion")))

	compiled, host := routerConfig(t, fmt.Sprintf(`root %q; compress brotli zstd gzip;`, filepath.ToSlash(directory)))

	router := New(compiled, Handoffs{})

	request := httptest.NewRequest("GET", "http://"+host+"/file.txt", nil)

	request.Header.Set("Accept-Encoding", "gzip, br")

	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Header().Get("Content-Encoding") != "br" || decodeBody(t, "br", recorder.Body.Bytes()) != "source" {
		t.Fatal("companion incorrectly overrode preferred encoding")
	}

	request.Header.Set("Accept-Encoding", "gzip")

	recorder = httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if decodeBody(t, "gzip", recorder.Body.Bytes()) != "companion" {
		t.Fatal("gzip companion not selected")
	}

	request.Header.Set("Accept-Encoding", "zstd")

	recorder = httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if decodeBody(t, "zstd", recorder.Body.Bytes()) != "zstd companion" {
		t.Fatal("alternate zstd suffix not selected")
	}

	request.Header.Set("Accept-Encoding", "*;q=0")

	recorder = httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != 406 {
		t.Fatal("all encodings excluded but response was accepted")
	}

	request.Header.Set("Accept-Encoding", "gzip")
	request.Header.Set("Cache-Control", "no-transform")

	recorder = httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Header().Get("Content-Encoding") != "" || recorder.Body.String() != "source" {
		t.Fatal("request no-transform ignored")
	}
}

func TestEmptyCompressionFrames(t *testing.T) {
	encodings := []config.Encoding{config.Gzip, config.Zstd, config.Brotli}

	for _, encoding := range encodings {
		body := encodeBody(t, encoding, "")
		if len(body) == 0 || decodeBody(t, encoding.String(), body) != "" {
			t.Fatalf("invalid empty %s frame", encoding)
		}
	}
}

func TestCompressionCacheLifecycle(t *testing.T) {
	directory := t.TempDir()

	writeFixture(t, directory, "file.txt", "first content")

	compiled, host := routerConfig(t, fmt.Sprintf(`root %q; compress gzip; compress_cache file;`, filepath.ToSlash(directory)))

	router := New(compiled, Handoffs{})

	router.compression.directory = t.TempDir()

	request := httptest.NewRequest("GET", "http://"+host+"/file.txt", nil)

	request.Header.Set("Accept-Encoding", "gzip")

	var workers sync.WaitGroup

	for range 8 {
		workers.Go(func() {
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			if recorder.Code != 200 {
				t.Errorf("concurrent compression: %d", recorder.Code)
			}
		})
	}

	workers.Wait()

	files, err := os.ReadDir(router.compression.directory)
	if err != nil || len(files) != 2 {
		t.Fatalf("cache publication left unexpected files: %v %v", files, err)
	}

	// A new router recovers the persistent index; a closed source proves a hit
	// does not read or hash the original bytes again.
	source, err := os.Open(filepath.Join(directory, "file.txt"))
	if err != nil {
		t.Fatal(err)
	}

	info, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}

	source.Close()

	cache := compressionCache{directory: router.compression.directory}
	key := compressionKey{Path: filepath.Join(directory, "file.txt"), Encoding: config.Gzip}

	content, err := cache.content(t.Context(), source, info, key, config.CompressCacheFile)
	if err != nil {
		t.Fatalf("persistent cache reread source: %v", err)
	}

	content.close()

	writeFixture(t, directory, "file.txt", "changed content")

	updated := time.Now().Add(time.Second)

	err = os.Chtimes(filepath.Join(directory, "file.txt"), updated, updated)
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if decodeBody(t, "gzip", recorder.Body.Bytes()) != "changed content" {
		t.Fatal("disk cache served stale bytes")
	}

	memory := compressionCache{limit: 6}

	stamp := sourceStamp{Size: 3, Modified: 1}

	first := compressionKey{Path: "first", Encoding: config.Gzip}
	second := compressionKey{Path: "second", Encoding: config.Gzip}
	third := compressionKey{Path: "third", Encoding: config.Gzip}

	memory.put(first, stamp, []byte("one"), "one")
	memory.put(second, stamp, []byte("two"), "two")

	active := memory.get(first, stamp)

	memory.put(third, stamp, []byte("tri"), "tri")

	if memory.get(second, stamp) != nil || memory.used != 6 || string(active.data) != "one" {
		t.Fatal("LRU eviction or active reader retention failed")
	}

	stamp.Modified++

	if memory.get(first, stamp) != nil {
		t.Fatal("memory cache retained stale source")
	}

	memory.put(first, stamp, []byte("oversized"), "large")

	if memory.get(first, stamp) != nil || memory.used > memory.limit {
		t.Fatal("oversized entry retained")
	}
}

func BenchmarkEncodingNegotiation(b *testing.B) {
	policy := config.CompressionPolicy{Algorithms: [3]config.Encoding{config.Zstd, config.Gzip, config.Brotli}, Count: 3}

	values := []string{"gzip;q=0.8, br;q=0.9, zstd, *;q=0.1"}

	b.ReportAllocs()

	for b.Loop() {
		negotiateEncoding(values, policy)
	}
}

func BenchmarkCompressionEncoder(b *testing.B) {
	encodings := []config.Encoding{config.Gzip, config.Zstd, config.Brotli}

	body := bytes.Repeat([]byte("compressible content\n"), 1000)

	for _, encoding := range encodings {
		b.Run(encoding.String(), func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				encoder, err := newCompressor(encoding, io.Discard)
				if err != nil {
					b.Fatal(err)
				}

				encoder.Write(body)
				encoder.Close()
			}
		})
	}
}

func encodeBody(t *testing.T, encoding config.Encoding, body string) []byte {
	t.Helper()

	var buffer bytes.Buffer

	encoder, err := newCompressor(encoding, &buffer)
	if err != nil {
		t.Fatal(err)
	}

	_, err = io.WriteString(encoder, body)
	if err != nil {
		t.Fatal(err)
	}

	err = encoder.Close()
	if err != nil {
		t.Fatal(err)
	}

	return buffer.Bytes()
}

func decodeBody(t *testing.T, encoding string, data []byte) string {
	t.Helper()

	var reader io.Reader

	switch encoding {
	case "gzip":
		decoder, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}

		defer decoder.Close()

		reader = decoder
	case "zstd":
		decoder, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderConcurrency(1))
		if err != nil {
			t.Fatal(err)
		}

		defer decoder.Close()

		reader = decoder
	case "br":
		reader = brotli.NewReader(bytes.NewReader(data))
	default:
		t.Fatalf("unknown encoding %q", encoding)
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}

	return string(body)
}
