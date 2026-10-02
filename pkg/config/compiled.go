package config

import (
	"fmt"
	"iter"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	NotFound HandlerKind = iota
	StaticRoot
	StaticAlias
	Proxy
	Return
)

const (
	CacheAuto CacheMode = iota
	CacheOff
	CacheEnabled
)

type HandlerKind uint8

type CacheMode uint8

type CachePolicy struct {
	Control string
	Seconds int64
	Mode    CacheMode
}

type headerOperation struct {
	name  string
	value string
	kind  string
}

type headerPlan struct {
	values []string
	name   string
	append bool
}

// Identity retains resolved key paths for the future Tor service setup. Loading
// validates their contents; service setup must revalidate if it rereads them.
type Identity struct {
	Name           string
	PrivateKeyPath string
	PublicKeyPath  string
}

// Route is immutable after compilation and safe for concurrent use.
type Route struct {
	upstream    url.URL
	cache       CachePolicy
	headers     []headerPlan
	indexes     []string
	path        string
	proxyPath   string
	body        string
	aliasPrefix string
	position    Position
	status      int
	kind        HandlerKind
	buffer      bool
	aliasExact  bool
}

type regexRoute struct {
	pattern *regexp.Regexp
	route   *Route
}

type prefixNode struct {
	children []*prefixNode
	prefix   string
	route    *Route
	priority bool
}

type server struct {
	prefix   prefixNode
	identity Identity
	regex    []regexRoute
	fallback *Route
	exact    map[string]*Route
	position Position
}

// Config contains a fully validated routing table. Match expects a normalized,
// decoded URL path; HTTP request normalization is performed by package router.
type Config struct {
	servers    map[string]*server
	identities []Identity
	fallback   *Route
}

func (r *Route) Kind() HandlerKind {
	return r.kind
}

func (r *Route) Position() Position {
	return r.position
}

func (r *Route) Cache() CachePolicy {
	return r.cache
}

func (r *Route) Buffered() bool {
	return r.buffer
}

func (r *Route) Status() int {
	return r.status
}

func (r *Route) Body() string {
	return r.body
}

func (r *Route) IndexCount() int {
	return len(r.indexes)
}

func (r *Route) Index(index int) string {
	return r.indexes[index]
}

func (r *Route) ApplyHeaders(headers http.Header) {
	for index := range r.headers {
		plan := &r.headers[index]
		if plan.append {
			headers[plan.name] = append(headers[plan.name], plan.values...)

			continue
		}

		if len(plan.values) == 0 {
			headers[plan.name] = nil

			continue
		}

		values := headers[plan.name]

		if cap(values) < len(plan.values) {
			values = make([]string, len(plan.values))
		} else {
			values = values[:len(plan.values)]
		}

		copy(values, plan.values)

		headers[plan.name] = values
	}
}

// ProxyURL preserves the request query while replacing or joining the path.
func (r *Route) ProxyURL(requestPath, rawQuery string) url.URL {
	target := r.upstream

	if r.proxyPath != "" {
		target.Path = r.proxyPath
	} else if target.Path == "/" {
		target.Path = requestPath
	} else {
		target.Path = strings.TrimSuffix(target.Path, "/") + "/" + strings.TrimPrefix(requestPath, "/")
	}

	target.RawPath = ""
	target.RawQuery = rawQuery

	return target
}

// StaticPath computes a lexical target only. The future file opener must enforce
// symlink containment against the configured root when it accesses the filesystem.
func (r *Route) StaticPath(requestPath string) (string, error) {
	if r.aliasExact {
		return r.path, nil
	}

	suffix := requestPath

	if r.kind == StaticAlias && r.aliasPrefix != "" {
		suffix = strings.TrimPrefix(suffix, r.aliasPrefix)
	}

	suffix = strings.TrimLeft(suffix, "/")
	if suffix == "" {
		return r.path, nil
	}

	local := filepath.FromSlash(suffix)
	if !filepath.IsLocal(local) || strings.ContainsAny(suffix, "\\\x00:") {
		return "", fmt.Errorf("request path cannot map to a local file")
	}

	return filepath.Join(r.path, local), nil
}

func (config *Config) ServerCount() int {
	return len(config.servers)
}

func (config *Config) Identities() iter.Seq[Identity] {
	return func(yield func(Identity) bool) {
		for _, identity := range config.identities {
			if !yield(identity) {
				return
			}
		}
	}
}

// Fallback supplies server or HTTP-level policy for generated error responses.
func (config *Config) Fallback(name string) *Route {
	server := config.servers[name]
	if server != nil {
		return server.fallback
	}

	return config.fallback
}

func (config *Config) Match(name, requestPath string) *Route {
	server := config.servers[name]
	if server == nil {
		return nil
	}

	exact := server.exact[requestPath]
	if exact != nil {
		return exact
	}

	prefix, priority := server.prefix.match(requestPath)
	if priority {
		return prefix
	}

	for index := range server.regex {
		candidate := &server.regex[index]
		if candidate.pattern.MatchString(requestPath) {
			return candidate.route
		}
	}

	if prefix != nil {
		return prefix
	}

	return server.fallback
}

func (node *prefixNode) insert(prefix string, route *Route, priority bool) {
	for _, child := range node.children {
		common := commonPrefix(prefix, child.prefix)
		if common == 0 {
			continue
		}

		if common < len(child.prefix) {
			suffix := *child

			suffix.prefix = suffix.prefix[common:]

			child.prefix = child.prefix[:common]
			child.route = nil
			child.priority = false
			child.children = []*prefixNode{&suffix}
		}

		if common == len(prefix) {
			child.route = route
			child.priority = priority
		} else {
			child.insert(prefix[common:], route, priority)
		}

		return
	}

	node.children = append(node.children, &prefixNode{prefix: prefix, route: route, priority: priority})
}

func (node *prefixNode) match(requestPath string) (*Route, bool) {
	var (
		matched  *Route
		priority bool
	)

	for {
		var next *prefixNode

		for _, child := range node.children {
			if strings.HasPrefix(requestPath, child.prefix) {
				next = child

				break
			}
		}

		if next == nil {
			return matched, priority
		}

		requestPath = requestPath[len(next.prefix):]

		if next.route != nil {
			matched = next.route
			priority = next.priority
		}

		node = next
	}
}

// NormalizePath accepts an already percent-decoded URL.Path, never a raw URI.
// A second unescape would turn escaped percent signs into traversal sequences.
func NormalizePath(value string) (string, error) {
	if value == "" {
		return "/", nil
	}

	if value[0] != '/' || strings.ContainsAny(value, "\\\x00\r\n") {
		return "", fmt.Errorf("invalid URL path")
	}

	cleaned := path.Clean(value)
	if cleaned != "/" && strings.HasSuffix(value, "/") {
		cleaned += "/"
	}

	return cleaned, nil
}

func commonPrefix(first, second string) int {
	limit := min(len(first), len(second))

	for index := range limit {
		if first[index] != second[index] {
			return index
		}
	}

	return limit
}
