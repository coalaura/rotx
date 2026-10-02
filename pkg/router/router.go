// Package router serves compiled routes, static files, and HTTP upstreams.
package router

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/coalaura/rotx/pkg/config"
)

// StaticTarget is a prepared lexical path and its compiled filesystem policy.
type StaticTarget struct {
	Path  string
	Route *config.Route
}

// Handoffs optionally override the built-in HTTP and filesystem handlers.
// Static handlers set metadata before writing their status or body. Error is an
// optional application-level reporter, e.g. a closure using the global logger.
type Handoffs struct {
	Transport http.RoundTripper
	Proxy     func(*Response, *http.Request, url.URL) error
	Static    func(*Response, *http.Request, StaticTarget) error
	Error     func(*http.Request, error)
}

type Router struct {
	handoffs  Handoffs
	transport http.RoundTripper
	config    *config.Config
}

type streamError struct {
	err error
}

func (err *streamError) Error() string {
	return err.err.Error()
}

func (err *streamError) Unwrap() error {
	return err.err
}

// CloseIdleConnections releases idle upstream connections when retiring a router.
func (r *Router) CloseIdleConnections() {
	if closer, ok := r.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (r *Router) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	err := r.Handle(writer, request)
	if err != nil && r.handoffs.Error != nil {
		r.handoffs.Error(request, err)
	}

	_, interrupted := errors.AsType[*streamError](err)
	if interrupted {
		// Do not terminate a truncated streaming response as a successful body.
		panic(http.ErrAbortHandler)
	}
}

// Handle writes an HTTP response and also returns any handoff/write error to its
// caller. Once a streaming response has committed, errors cannot change status.
func (r *Router) Handle(writer http.ResponseWriter, request *http.Request) error {
	name := onionHost(request.Host)

	requestPath, err := config.NormalizePath(request.URL.Path)
	if err != nil {
		response := newResponse(writer, request, r.config.Fallback(name))

		writeStatus(response, request, http.StatusBadRequest, "Bad Request\n")

		response.finish()

		return err
	}

	route := r.config.Match(name, requestPath)
	if route == nil {
		response := newResponse(writer, request, r.config.Fallback(""))

		writeStatus(response, request, http.StatusNotFound, "Not Found\n")

		return response.finish()
	}

	// Copy only when normalization changes the URL; the caller's request remains
	// untouched and the clean-path routing hot path needs no request clone.
	if requestPath != request.URL.Path {
		clone := new(*request)

		clone.URL = new(*request.URL)
		clone.URL.Path = requestPath
		clone.URL.RawPath = ""

		request = clone
	}

	response := newResponse(writer, request, route)

	err = r.dispatch(response, request, route, requestPath)
	if err != nil {
		if response.committed {
			return &streamError{err: err}
		}

		status := http.StatusInternalServerError

		if route.Kind() == config.Proxy {
			status = http.StatusBadGateway
		}

		response.fail(status)
	}

	finishError := response.finish()

	if err != nil {
		return err
	}

	if finishError != nil && response.committed {
		return &streamError{err: finishError}
	}

	return finishError
}

func (r *Router) dispatch(response *Response, request *http.Request, route *config.Route, requestPath string) error {
	switch route.Kind() {
	case config.Proxy:
		if r.handoffs.Proxy != nil {
			return r.handoffs.Proxy(response, request, route.ProxyURL(requestPath, request.URL.RawQuery))
		}

		return r.proxy(response, request, route.ProxyURL(requestPath, request.URL.RawQuery))
	case config.StaticRoot, config.StaticAlias:
		target, err := route.StaticPath(requestPath)
		if err != nil {
			writeStatus(response, request, http.StatusBadRequest, "Bad Request\n")

			return err
		}

		if r.handoffs.Static != nil {
			return r.handoffs.Static(response, request, StaticTarget{Path: target, Route: route})
		}

		return serveStatic(response, request, StaticTarget{Path: target, Route: route})
	case config.Return:
		return writeStatus(response, request, route.Status(), route.Body())
	default:
		return writeStatus(response, request, http.StatusNotFound, "Not Found\n")
	}
}

func New(compiled *config.Config, handoffs Handoffs) *Router {
	transport := handoffs.Transport
	if transport == nil {
		transport = newTransport()
	}

	return &Router{config: compiled, handoffs: handoffs, transport: transport}
}

func onionHost(host string) string {
	if strings.Contains(host, ":") {
		name, _, err := net.SplitHostPort(host)
		if err != nil {
			return ""
		}

		host = name
	}

	host = strings.TrimSuffix(host, ".")
	if len(host) != 62 || !strings.EqualFold(host[56:], ".onion") {
		return ""
	}

	return strings.ToLower(host[:56])
}

func writeStatus(response *Response, request *http.Request, status int, body string) error {
	response.Header().Set("Content-Type", "text/plain; charset=utf-8")

	if status != http.StatusNoContent && status != http.StatusResetContent && status != http.StatusNotModified {
		response.Header().Set("Content-Length", strconv.Itoa(len(body)))
	}

	response.WriteHeader(status)

	if request.Method == http.MethodHead || body == "" {
		return nil
	}

	_, err := io.WriteString(response, body)
	return err
}

func handoffError(status int) string {
	return http.StatusText(status) + "\n"
}
