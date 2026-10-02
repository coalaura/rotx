// Package router executes compiled routes up to the proxy/filesystem handoff.
package router

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/coalaura/rotx/pkg/config"
)

// StaticTarget is a prepared lexical path. A file-serving implementation must
// enforce symlink containment and try Route.Index entries for directories.
type StaticTarget struct {
	Path  string
	Route *config.Route
}

// Handoffs are optional. Missing handlers return 501 without network or file I/O.
// Static handlers set metadata before writing their status or body. Error is an
// optional application-level reporter, e.g. a closure using the global logger.
type Handoffs struct {
	Proxy  func(*Response, *http.Request, url.URL) error
	Static func(*Response, *http.Request, StaticTarget) error
	Error  func(*http.Request, error)
}

type Router struct {
	handoffs Handoffs
	config   *config.Config
}

func (router *Router) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	err := router.Handle(writer, request)
	if err != nil && router.handoffs.Error != nil {
		router.handoffs.Error(request, err)
	}
}

// Handle writes an HTTP response and also returns any handoff/write error to its
// caller. Once a streaming response has committed, errors cannot change status.
func (router *Router) Handle(writer http.ResponseWriter, request *http.Request) error {
	name := onionHost(request.Host)

	requestPath, err := config.NormalizePath(request.URL.Path)
	if err != nil {
		response := newResponse(writer, request, router.config.Fallback(name))

		writeStatus(response, request, http.StatusBadRequest, "Bad Request\n")

		response.finish()

		return err
	}

	route := router.config.Match(name, requestPath)
	if route == nil {
		response := newResponse(writer, request, router.config.Fallback(""))

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

	err = router.dispatch(response, request, route, requestPath)
	if err != nil {
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

	return finishError
}

func (router *Router) dispatch(response *Response, request *http.Request, route *config.Route, requestPath string) error {
	switch route.Kind() {
	case config.Proxy:
		if router.handoffs.Proxy != nil {
			return router.handoffs.Proxy(response, request, route.ProxyURL(requestPath, request.URL.RawQuery))
		}
	case config.StaticRoot, config.StaticAlias:
		target, err := route.StaticPath(requestPath)
		if err != nil {
			writeStatus(response, request, http.StatusBadRequest, "Bad Request\n")

			return err
		}

		if router.handoffs.Static != nil {
			return router.handoffs.Static(response, request, StaticTarget{Path: target, Route: route})
		}
	case config.Return:
		return writeStatus(response, request, route.Status(), route.Body())
	default:
		return writeStatus(response, request, http.StatusNotFound, "Not Found\n")
	}

	return writeStatus(response, request, http.StatusNotImplemented, "Not Implemented\n")
}

func New(compiled *config.Config, handoffs Handoffs) *Router {
	return &Router{config: compiled, handoffs: handoffs}
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
