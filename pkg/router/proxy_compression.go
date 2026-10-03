package router

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/coalaura/rotx/pkg/config"
)

func (r *Response) prepareProxyCompression() {
	policy := r.route.Compression()
	if !r.route.ProxyCompress() || policy.Count == 0 || r.status < 200 || r.status == 204 || r.status == 205 || r.status == 304 || r.status == 206 {
		return
	}

	headers := r.snapshot

	encoded := headers.Get("Content-Encoding")
	media, _, _ := strings.Cut(headers.Get("Content-Type"), ";")

	if encoded != "" && !strings.EqualFold(encoded, "identity") || headers.Get("Content-Range") != "" || strings.EqualFold(strings.TrimSpace(media), "text/event-stream") || noTransform(headers) || noTransform(r.request.Header) {
		return
	}

	varyEncoding(headers)

	encoding, acceptable := negotiateEncoding(r.request.Header.Values("Accept-Encoding"), policy)
	if !acceptable {
		r.status = http.StatusNotAcceptable
		r.suppress = true

		headers.Del("Content-Length")
		headers.Del("Content-Encoding")

		return
	}

	if encoding == config.IdentityEncoding {
		return
	}

	r.encoding = encoding

	headers.Set("Content-Encoding", encoding.String())

	headers.Del("Content-Length")
	headers.Del("Accept-Ranges")
	headers.Del("Content-Md5")
	headers.Del("Digest")
	headers.Del("Content-Digest")
	headers.Del("Repr-Digest")

	tag := headers.Get("Etag")
	if validETag(tag) && !strings.HasPrefix(tag, "W/") {
		headers.Set("Etag", "W/"+tag)
	}

	// The original representation's integrity and validator trailers no longer
	// describe the outgoing bytes. Other application trailers remain valid.
	headers.Del("Trailer")

	for _, value := range r.headers.Values("Trailer") {
		for name := range strings.SplitSeq(value, ",") {
			name = strings.TrimSpace(name)
			if allowedTrailer(name, r) {
				headers.Add("Trailer", name)
			}
		}
	}
}

func (r *Response) writeCompressed(body []byte) (int, error) {
	if r.encoder == nil {
		encoder, err := newCompressor(r.encoding, r.writer)
		if err != nil {
			return 0, err
		}

		r.encoder = encoder
	}

	return r.encoder.Write(body)
}

func (r *Response) finishCompression() error {
	if r.encoding == config.IdentityEncoding || r.suppress || r.request.Method == http.MethodHead {
		return nil
	}

	// Even an empty encoded response requires a valid codec frame.
	_, err := r.writeCompressed(nil)
	if err != nil {
		return err
	}

	err = r.encoder.Close()

	r.encoder = nil

	return err
}

// abortCompression releases codec resources without writing a successful footer
// after an upstream read failure. The HTTP transport aborts the response.
func (r *Response) abortCompression() {
	if r.encoder == nil {
		return
	}

	// Closing after an error may flush buffered data; all writes go to discard.
	r.encoder.Reset(io.Discard)

	r.encoder.Close()
	r.encoder = nil
}

func (r *Response) flushCompression() error {
	if r.encoder == nil {
		return nil
	}

	err := r.encoder.Flush()
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		r.err = err
	}

	return err
}

func transformedTrailer(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Etag", "Content-Md5", "Digest", "Content-Digest", "Repr-Digest", "Accept-Ranges":
		return true
	}

	return false
}
