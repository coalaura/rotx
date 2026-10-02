package config

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type scope struct {
	values   map[string]*statement
	headers  []headerOperation
	children []*statement
}

func compileConfig(statements []statement, position Position) (*Config, error) {
	if len(statements) != 1 || statements[0].name != "http" || !statements[0].block || len(statements[0].args) != 0 {
		if len(statements) > 0 {
			position = statements[min(1, len(statements)-1)].position
		}

		return nil, diagnostic(position, "configuration requires exactly one top-level http block with no arguments")
	}

	httpBlock := &statements[0]

	global, err := readScope(httpBlock, "http")
	if err != nil {
		return nil, err
	}

	if len(global.children) == 0 {
		return nil, diagnostic(httpBlock.position, "http requires at least one server")
	}

	base := Route{
		headers: compileHeaderPlans(nil, global.headers),
		indexes: []string{"index.html"},
	}

	config := &Config{
		servers:    make(map[string]*server, len(global.children)),
		identities: make([]Identity, 0, len(global.children)),
		fallback:   &base,
	}

	for _, block := range global.children {
		name, compiled, err := compileServer(block, &base)
		if err != nil {
			return nil, err
		}

		previous := config.servers[name]
		if previous != nil {
			return nil, diagnostic(block.position, "duplicate onion identity %s; first declared at %s", name, previous.position)
		}

		config.servers[name] = compiled

		config.identities = append(config.identities, compiled.identity)
	}

	return config, nil
}

func compileServer(block *statement, parent *Route) (string, *server, error) {
	parsed, err := readScope(block, "server")
	if err != nil {
		return "", nil, err
	}

	required := []string{"name", "key_private", "key_public"}

	for _, name := range required {
		if parsed.values[name] == nil {
			return "", nil, diagnostic(block.position, "server requires %s", name)
		}
	}

	nameDirective := parsed.values["name"]
	private := parsed.values["key_private"]
	public := parsed.values["key_public"]

	name := nameDirective.args[0].value

	identity := Identity{
		Name:           name,
		PrivateKeyPath: resolveFile(private.position.File, private.args[0].value),
		PublicKeyPath:  resolveFile(public.position.File, public.args[0].value),
	}

	err = validateIdentity(identity.Name, identity.PrivateKeyPath, identity.PublicKeyPath)
	if err != nil {
		return "", nil, diagnostic(nameDirective.position, "%v", err)
	}

	fallback, err := compileRoute(block, &parsed, parent)
	if err != nil {
		return "", nil, err
	}

	compiled := &server{
		identity: identity,
		fallback: fallback,
		exact:    make(map[string]*Route),
		position: block.position,
	}

	prefixes := make(map[string]Position, len(parsed.children))

	for _, location := range parsed.children {
		mode, pattern, err := locationPattern(location)
		if err != nil {
			return "", nil, err
		}

		local, err := readScope(location, "location")
		if err != nil {
			return "", nil, err
		}

		route, err := compileRoute(location, &local, fallback)
		if err != nil {
			return "", nil, err
		}

		if local.values["alias"] != nil {
			switch mode {
			case "~":
				return "", nil, diagnostic(location.position, "alias is not supported in regex locations")
			case "=":
				route.aliasExact = true
			default:
				route.aliasPrefix = pattern
			}
		}

		switch mode {
		case "=":
			previous := compiled.exact[pattern]
			if previous != nil {
				return "", nil, diagnostic(location.position, "duplicate exact location; first declared at %s", previous.position)
			}

			compiled.exact[pattern] = route
		case "~":
			expression, err := regexp.Compile(pattern)
			if err != nil {
				return "", nil, diagnostic(location.position, "invalid regular expression: %v", err)
			}

			compiled.regex = append(compiled.regex, regexRoute{pattern: expression, route: route})
		default:
			if previous, exists := prefixes[pattern]; exists {
				return "", nil, diagnostic(location.position, "duplicate prefix location; first declared at %s", previous)
			}

			prefixes[pattern] = location.position

			compiled.prefix.insert(pattern, route, mode == "^~")
		}
	}

	return name, compiled, nil
}

func readScope(block *statement, kind string) (scope, error) {
	parsed := scope{values: make(map[string]*statement, len(block.children))}

	var returned bool

	for index := range block.children {
		current := &block.children[index]

		if returned {
			return parsed, diagnostic(current.position, "return must be the last directive in its location")
		}

		if current.block {
			allowed := kind == "http" && current.name == "server" || kind == "server" && current.name == "location"
			if !allowed {
				return parsed, diagnostic(current.position, "block %q is not allowed in %s", current.name, kind)
			}

			if current.name == "server" && len(current.args) != 0 {
				return parsed, diagnostic(current.position, "server takes no arguments")
			}

			parsed.children = append(parsed.children, current)

			continue
		}

		minimum, maximum, allowed := directiveSpec(current.name, kind)
		if !allowed {
			return parsed, diagnostic(current.position, "unknown or misplaced directive %q in %s", current.name, kind)
		}

		if len(current.args) < minimum || len(current.args) > maximum {
			return parsed, diagnostic(current.position, "incorrect argument count for %s", current.name)
		}

		if strings.HasPrefix(current.name, "header_") {
			operation, err := compileHeader(current)
			if err != nil {
				return parsed, err
			}

			parsed.headers = append(parsed.headers, operation)

			continue
		}

		previous := parsed.values[current.name]
		if previous != nil {
			return parsed, diagnostic(current.position, "duplicate %s; first declared at %s", current.name, previous.position)
		}

		parsed.values[current.name] = current

		returned = current.name == "return"
	}

	return parsed, nil
}

func compileRoute(block *statement, parsed *scope, parent *Route) (*Route, error) {
	route := *parent

	route.position = block.position
	route.headers = compileHeaderPlans(parent.headers, parsed.headers)

	handlers := []string{"root", "alias", "proxy_pass", "return"}

	var handler *statement

	for _, name := range handlers {
		current := parsed.values[name]
		if current == nil {
			continue
		}

		if handler != nil {
			return nil, diagnostic(current.position, "%s conflicts with %s at %s", name, handler.name, handler.position)
		}

		handler = current
	}

	if handler != nil {
		err := setHandler(&route, handler)
		if err != nil {
			return nil, err
		}
	}

	current := parsed.values["cache"]
	if current != nil {
		policy, err := parseCache(current.args[0].value)
		if err != nil {
			return nil, diagnostic(current.position, "%v", err)
		}

		route.cache = policy
	}

	current = parsed.values["index"]
	if current != nil {
		route.indexes = make([]string, 0, len(current.args))

		for _, argument := range current.args {
			if argument.value == "." || argument.value == ".." || !filepath.IsLocal(argument.value) || strings.ContainsAny(argument.value, "/\\\x00:") {
				return nil, diagnostic(argument.position, "index must be a local filename")
			}

			route.indexes = append(route.indexes, argument.value)
		}
	}

	current = parsed.values["proxy_path"]
	if current != nil {
		if route.kind != Proxy {
			return nil, diagnostic(current.position, "proxy_path requires proxy_pass")
		}

		normalized, err := configuredPath(current.args[0].value)
		if err != nil {
			return nil, diagnostic(current.position, "proxy_path: %v", err)
		}

		route.proxyPath = normalized
	}

	current = parsed.values["proxy_buffer"]
	if current != nil {
		value := current.args[0].value
		if route.kind != Proxy || value != "on" && value != "off" {
			return nil, diagnostic(current.position, "proxy_buffer requires proxy_pass and on or off")
		}

		route.buffer = value == "on"
	}

	return &route, nil
}

func setHandler(route *Route, current *statement) error {
	value := current.args[0].value

	switch current.name {
	case "root", "alias":
		if value == "" || strings.ContainsRune(value, 0) {
			return diagnostic(current.position, "empty or invalid filesystem path")
		}

		route.kind = StaticRoot

		if current.name == "alias" {
			route.kind = StaticAlias
		}

		route.path = resolveFile(current.position.File, value)
	case "proxy_pass":
		upstream, err := url.Parse(value)
		if err != nil {
			return diagnostic(current.position, "invalid proxy_pass URL: %v", err)
		}

		if upstream.Scheme != "http" && upstream.Scheme != "https" || upstream.Hostname() == "" || upstream.User != nil || upstream.RawQuery != "" || upstream.ForceQuery || strings.Contains(value, "#") || upstream.Opaque != "" {
			return diagnostic(current.position, "proxy_pass requires an HTTP(S) URL without credentials, query, or fragment")
		}

		port := upstream.Port()
		if port != "" {
			number, err := strconv.ParseUint(port, 10, 16)
			if err != nil || number == 0 {
				return diagnostic(current.position, "invalid upstream port")
			}
		}

		normalized, err := NormalizePath(upstream.Path)
		if err != nil {
			return diagnostic(current.position, "invalid upstream path: %v", err)
		}

		upstream.Path = normalized
		upstream.RawPath = ""

		route.kind = Proxy
		route.upstream = *upstream
	case "return":
		status, err := strconv.Atoi(value)
		if err != nil || status < 200 || status > 599 || http.StatusText(status) == "" {
			return diagnostic(current.position, "return requires a standard final HTTP status (200-599)")
		}

		route.kind = Return
		route.status = status
		route.body = http.StatusText(status) + "\n"

		if len(current.args) == 2 {
			if status == 204 || status == 205 || status == 304 {
				return diagnostic(current.position, "status %d cannot have a response body", status)
			}

			route.body = current.args[1].value
		}

		if status == 204 || status == 205 || status == 304 {
			route.body = ""
		}
	}

	return nil
}

func locationPattern(block *statement) (string, string, error) {
	mode := ""

	if len(block.args) == 0 || len(block.args) > 2 {
		return "", "", diagnostic(block.position, "location requires a path with an optional =, ^~, or ~ modifier")
	}

	argument := block.args[0]

	if len(block.args) == 2 {
		mode = argument.value
		argument = block.args[1]

		if mode != "=" && mode != "^~" && mode != "~" {
			return "", "", diagnostic(block.position, "unsupported location modifier %q", mode)
		}
	}

	if mode == "~" {
		if !argument.quoted {
			return "", "", diagnostic(argument.position, "regular expressions must be quoted")
		}

		return mode, argument.value, nil
	}

	pattern, err := configuredPath(argument.value)
	if err != nil {
		return "", "", diagnostic(argument.position, "invalid location path: %v", err)
	}

	return mode, pattern, nil
}

func directiveSpec(name, scope string) (int, int, bool) {
	switch name {
	case "header_set", "header_add":
		return 2, 2, true
	case "header_unset":
		return 1, 1, true
	case "name", "key_private", "key_public":
		return 1, 1, scope == "server"
	case "root", "alias", "cache":
		return 1, 1, scope == "server" || scope == "location"
	case "index":
		return 1, math.MaxInt, scope == "server" || scope == "location"
	case "proxy_pass", "proxy_path", "proxy_buffer":
		return 1, 1, scope == "location"
	case "return":
		return 1, 2, scope == "location"
	}

	return 0, 0, false
}

func compileHeader(current *statement) (headerOperation, error) {
	name := current.args[0].value
	if name == "" {
		return headerOperation{}, diagnostic(current.position, "empty header name")
	}

	for _, character := range name {
		valid := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", character)
		if !valid {
			return headerOperation{}, diagnostic(current.position, "invalid header name %q", name)
		}
	}

	name = http.CanonicalHeaderKey(name)

	switch name {
	case "Content-Length", "Transfer-Encoding", "Connection", "Trailer", "Upgrade", "Keep-Alive", "Proxy-Connection":
		return headerOperation{}, diagnostic(current.position, "%s is controlled by the HTTP transport", name)
	}

	value := ""

	if len(current.args) == 2 {
		value = current.args[1].value

		for _, character := range value {
			if character < 32 && character != '\t' || character == 127 {
				return headerOperation{}, diagnostic(current.position, "invalid control character in header value")
			}
		}
	}

	return headerOperation{name: name, value: value, kind: current.name}, nil
}

func configuredPath(value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "?#") {
		return "", fmt.Errorf("expected an absolute path without query or fragment")
	}

	decoded, err := url.PathUnescape(value)
	if err != nil {
		return "", err
	}

	return NormalizePath(decoded)
}

func parseCache(value string) (CachePolicy, error) {
	switch value {
	case "auto":
		return CachePolicy{Mode: CacheAuto}, nil
	case "off":
		return CachePolicy{Mode: CacheOff, Control: "no-store"}, nil
	case "on":
		return CachePolicy{Mode: CacheEnabled, Seconds: 3600, Control: "public, max-age=3600"}, nil
	}

	if len(value) < 2 {
		return CachePolicy{}, fmt.Errorf("invalid cache duration %q", value)
	}

	var multiplier int64

	switch value[len(value)-1] {
	case 'd':
		multiplier = 86400
	case 'h':
		multiplier = 3600
	case 'm':
		multiplier = 60
	case 's':
		multiplier = 1
	default:
		return CachePolicy{}, fmt.Errorf("cache duration must use d, h, m, or s")
	}

	digits := value[:len(value)-1]
	if strings.Trim(digits, "0123456789") != "" {
		return CachePolicy{}, fmt.Errorf("cache duration must be a positive integer and one unit")
	}

	number, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || number <= 0 || number > math.MaxInt64/multiplier {
		return CachePolicy{}, fmt.Errorf("cache duration is invalid or overflows")
	}

	seconds := number * multiplier

	return CachePolicy{Mode: CacheEnabled, Seconds: seconds, Control: "public, max-age=" + strconv.FormatInt(seconds, 10)}, nil
}
