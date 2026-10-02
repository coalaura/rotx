package router

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coalaura/rotx/pkg/config"
)

// Metadata describes a selected static representation. ETag may be a strong
// content-derived tag; an empty tag produces a weak size/mtime validator.
type Metadata struct {
	Modified time.Time
	ETag     string
	Size     int64
}

// Response defers header transformations until final status commitment. With
// proxy_buffer enabled it retains the whole body until the handoff returns.
// Like net/http.ResponseWriter, it is used by one request goroutine at a time.
type Response struct {
	metadata    Metadata
	body        bytes.Buffer
	writer      http.ResponseWriter
	err         error
	request     *http.Request
	route       *config.Route
	headers     http.Header
	snapshot    http.Header
	trailers    http.Header
	status      int
	committed   bool
	suppress    bool
	hasMetadata bool
}

func (r *Response) Header() http.Header {
	return r.headers
}

// SetMetadata must precede WriteHeader/Write and is meaningful only for static
// routes. It performs no file access and leaves proxy validators untouched.
func (r *Response) SetMetadata(metadata Metadata) error {
	if r.status != 0 {
		return fmt.Errorf("metadata must be set before response status")
	}

	kind := r.route.Kind()
	if kind != config.StaticRoot && kind != config.StaticAlias {
		return fmt.Errorf("metadata is only valid for static responses")
	}

	if metadata.Modified.IsZero() || metadata.Size < 0 || metadata.ETag != "" && !validETag(metadata.ETag) {
		return fmt.Errorf("invalid static metadata")
	}

	r.metadata = metadata
	r.hasMetadata = true

	return nil
}

func (r *Response) WriteHeader(status int) {
	if status < 100 || status > 999 {
		panic("invalid HTTP status code")
	}

	if r.status != 0 {
		return
	}

	// Informational responses do not finalize the response. Do not publish them
	// while body buffering is enabled, where the final response is still pending.
	if status < 200 {
		if !r.route.Buffered() {
			headers := r.headers.Clone()

			r.route.ApplyHeaders(headers)

			copyHeaders(r.writer.Header(), headers)

			r.writer.WriteHeader(status)
		}

		return
	}

	r.status = status
	r.snapshot = r.headers.Clone()

	r.prepare()

	if !r.route.Buffered() {
		r.commit()
	}
}

func (r *Response) Write(body []byte) (int, error) {
	if r.status == 0 {
		if r.headers.Get("Content-Type") == "" && len(body) > 0 {
			r.headers.Set("Content-Type", http.DetectContentType(body))
		}

		r.WriteHeader(http.StatusOK)
	}

	if r.suppress || r.request.Method == http.MethodHead {
		return len(body), nil
	}

	if r.route.Buffered() {
		return r.body.Write(body)
	}

	written, err := r.writer.Write(body)
	if err != nil {
		r.err = err
	}

	return written, err
}

func (r *Response) WriteString(body string) (int, error) {
	if r.status == 0 {
		if r.headers.Get("Content-Type") == "" && len(body) > 0 {
			prefix := []byte(body[:min(len(body), 512)])

			r.headers.Set("Content-Type", http.DetectContentType(prefix))
		}

		r.WriteHeader(http.StatusOK)
	}

	if r.suppress || r.request.Method == http.MethodHead {
		return len(body), nil
	}

	if r.route.Buffered() {
		return r.body.WriteString(body)
	}

	written, err := io.WriteString(r.writer, body)
	if err != nil {
		r.err = err
	}

	return written, err
}

// FlushError supports http.ResponseController without allowing Flush to bypass
// configured buffering. Streaming flushes commit the final header policy first.
func (r *Response) FlushError() error {
	if r.route.Buffered() {
		return nil
	}

	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}

	err := http.NewResponseController(r.writer).Flush()
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		r.err = err
	}

	return err
}

func (r *Response) Flush() {
	r.FlushError()
}

func (r *Response) prepare() {
	headers := r.snapshot

	cache := r.route.Cache()
	if cache.Mode != config.CacheAuto {
		headers.Set("Cache-Control", cache.Control)

		headers.Del("Expires")
		headers.Del("Pragma")
	}

	if cache.Mode == config.CacheEnabled && r.hasMetadata && r.status == http.StatusOK {
		r.setValidators(headers)

		if notModified(r.request, headers.Get("Etag"), r.metadata.Modified) {
			r.status = http.StatusNotModified
		}
	}

	if r.status == http.StatusNoContent || r.status == http.StatusResetContent || r.status == http.StatusNotModified {
		r.suppress = true

		headers.Del("Content-Length")

		if r.status == http.StatusNotModified {
			headers.Del("Content-Type")
		}
	}

	r.route.ApplyHeaders(headers)
}

func (r *Response) setValidators(headers http.Header) {
	metadata := r.metadata

	tag := metadata.ETag
	if tag == "" {
		tag = `W/"` + strconv.FormatInt(metadata.Modified.UnixNano(), 16) + "-" + strconv.FormatInt(metadata.Size, 16) + `"`
	}

	headers.Set("Etag", tag)
	headers.Set("Last-Modified", metadata.Modified.UTC().Format(http.TimeFormat))
}

func (r *Response) commit() {
	copyHeaders(r.writer.Header(), r.snapshot)

	r.writer.WriteHeader(r.status)

	r.committed = true
}

func (r *Response) finish() error {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}

	if !r.committed {
		for name := range r.trailers {
			r.snapshot.Add("Trailer", name)
			r.snapshot.Del("Content-Length")
		}

		r.commit()

		if !r.suppress && r.request.Method != http.MethodHead {
			_, err := r.body.WriteTo(r.writer)
			if err != nil {
				return err
			}
		}
	}

	for name, values := range r.trailers {
		r.writer.Header()[http.TrailerPrefix+name] = values
	}

	return r.err
}

func (r *Response) fail(status int) {
	if r.committed {
		return
	}

	r.status = 0
	r.snapshot = nil
	r.trailers = nil
	r.suppress = false
	r.hasMetadata = false

	r.body.Reset()

	clear(r.headers)

	writeStatus(r, r.request, status, handoffError(status))
}

func newResponse(writer http.ResponseWriter, request *http.Request, route *config.Route) *Response {
	return &Response{writer: writer, request: request, route: route, headers: make(http.Header)}
}

func notModified(request *http.Request, tag string, modified time.Time) bool {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		return false
	}

	values, present := request.Header["If-None-Match"]
	if present {
		for _, value := range values {
			if matchesETag(value, tag) {
				return true
			}
		}

		return false
	}

	value := request.Header.Get("If-Modified-Since")
	if value == "" {
		return false
	}

	since, err := http.ParseTime(value)
	return err == nil && !modified.Truncate(time.Second).After(since)
}

// Entity tags can contain commas, so splitting this header on commas is wrong.
func matchesETag(value, tag string) bool {
	tag = strings.TrimPrefix(tag, "W/")
	value = strings.TrimSpace(value)

	for value != "" {
		value = strings.TrimLeft(value, " \t,")
		if value == "*" {
			return true
		}

		value = strings.TrimPrefix(value, "W/")
		if len(value) < 2 || value[0] != '"' {
			return false
		}

		end := strings.IndexByte(value[1:], '"')
		if end < 0 {
			return false
		}

		candidate := value[:end+2]

		value = strings.TrimLeft(value[end+2:], " \t")
		if value != "" && value[0] != ',' {
			return false
		}

		if candidate == tag {
			return true
		}
	}

	return false
}

func validETag(value string) bool {
	value = strings.TrimPrefix(value, "W/")
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}

	for index := 1; index < len(value)-1; index++ {
		character := value[index]
		if character < 33 || character == '"' || character == 127 {
			return false
		}
	}

	return true
}

func copyHeaders(destination, source http.Header) {
	clear(destination)

	maps.Copy(destination, source)
}
