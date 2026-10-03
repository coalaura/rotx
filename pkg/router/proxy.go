package router

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coalaura/rotx/pkg/config"
)

type proxyRequestBody struct {
	body     io.ReadCloser
	source   http.Header
	trailers http.Header
}

func (b *proxyRequestBody) Read(destination []byte) (int, error) {
	count, err := b.body.Read(destination)
	if errors.Is(err, io.EOF) {
		for name := range b.trailers {
			b.trailers[name] = append(b.trailers[name][:0], b.source[name]...)
		}
	}

	return count, err
}

func (b *proxyRequestBody) Close() error {
	return b.body.Close()
}

func (r *Router) proxy(response *Response, request *http.Request, target url.URL) error {
	if request.Method == http.MethodConnect || request.Header.Get("Upgrade") != "" {
		return writeStatus(response, request, http.StatusNotImplemented, "Not Implemented\n")
	}

	outgoing := request.Clone(request.Context())

	outgoing.URL = &target
	outgoing.RequestURI = ""
	outgoing.Host = target.Host
	outgoing.Close = false
	outgoing.TransferEncoding = nil

	if len(outgoing.Trailer) > 0 && outgoing.Body != nil {
		removeConnectionHeaders(request.Header.Values("Connection"), outgoing.Trailer)

		for name := range outgoing.Trailer {
			if protocolTrailer(name) {
				delete(outgoing.Trailer, name)
			}
		}

		outgoing.Body = &proxyRequestBody{body: outgoing.Body, source: request.Trailer, trailers: outgoing.Trailer}
	}

	removeHopHeaders(outgoing.Header)

	// Forward only the public service identity, never a transport peer address.
	// Supplied forwarding chains are untrusted and can leak or spoof identities.
	outgoing.Header.Del("Forwarded")
	outgoing.Header.Del("X-Forwarded-For")
	outgoing.Header.Del("X-Real-Ip")
	outgoing.Header.Set("X-Forwarded-Host", request.Host)
	outgoing.Header.Set("X-Forwarded-Proto", "http")

	if request.TLS != nil {
		outgoing.Header.Set("X-Forwarded-Proto", "https")
	}

	if _, present := outgoing.Header["User-Agent"]; !present {
		outgoing.Header["User-Agent"] = nil
	}

	upstream, err := r.transport.RoundTrip(outgoing)
	if err != nil {
		return err
	}

	defer upstream.Body.Close()

	if upstream.StatusCode == http.StatusSwitchingProtocols {
		return fmt.Errorf("upstream protocol upgrades are not supported")
	}

	connections := upstream.Header.Values("Connection")

	removeConnectionHeaders(connections, upstream.Trailer)

	removeHopHeaders(upstream.Header)

	copyHeaders(response.Header(), upstream.Header)

	for name := range upstream.Trailer {
		if allowedTrailer(name, response) {
			response.Header().Add("Trailer", name)
			response.Header().Del("Content-Length")
		}
	}

	response.WriteHeader(upstream.StatusCode)

	if request.Method == http.MethodHead || response.suppress {
		return nil
	}

	if !response.route.Buffered() {
		err = response.FlushError()
		if err != nil && !errors.Is(err, http.ErrNotSupported) {
			return err
		}
	}

	// Flush each received chunk for streaming/SSE. Buffered routes keep both
	// headers and body private until the complete upstream response succeeds.
	var buffer [32 * 1024]byte

	for {
		count, readError := upstream.Body.Read(buffer[:])
		if count > 0 {
			written, writeError := response.Write(buffer[:count])
			if writeError != nil {
				return writeError
			}

			if written != count {
				return io.ErrShortWrite
			}

			if !response.route.Buffered() {
				err = response.FlushError()
				if err != nil && !errors.Is(err, http.ErrNotSupported) {
					return err
				}
			}
		}

		if errors.Is(readError, io.EOF) {
			removeConnectionHeaders(connections, upstream.Trailer)

			for name := range upstream.Trailer {
				if !allowedTrailer(name, response) {
					delete(upstream.Trailer, name)
				}
			}

			response.trailers = upstream.Trailer

			return nil
		}

		if readError != nil {
			return readError
		}
	}
}

func newTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}

	return &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
	}
}

func allowedTrailer(name string, response *Response) bool {
	if response.encoding != config.IdentityEncoding && transformedTrailer(name) {
		return false
	}

	if strings.EqualFold(name, "Server") && response.route.ServerTokens() != config.TokensKeep {
		return false
	}

	return !protocolTrailer(name) && !response.route.ControlsHeader(name)
}

func protocolTrailer(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Content-Length", "Content-Type", "Content-Encoding", "Content-Range", "Host", "Cache-Control", "Expires", "Pragma", "Authorization", "Www-Authenticate", "Set-Cookie", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip":
		return true
	}

	return false
}

func removeHopHeaders(headers http.Header) {
	removeConnectionHeaders(headers.Values("Connection"), headers)

	headers.Del("Connection")
	headers.Del("Proxy-Connection")
	headers.Del("Keep-Alive")
	headers.Del("Proxy-Authenticate")
	headers.Del("Proxy-Authorization")
	headers.Del("Te")
	headers.Del("Trailer")
	headers.Del("Transfer-Encoding")
	headers.Del("Upgrade")
}

func removeConnectionHeaders(values []string, headers http.Header) {
	for _, value := range values {
		for name := range strings.SplitSeq(value, ",") {
			headers.Del(strings.TrimSpace(name))
		}
	}
}
