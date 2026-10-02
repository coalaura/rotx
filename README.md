# rotx

An nginx-style configuration compiler and HTTP router for Tor onion services. It validates configuration and identities, serves static files, proxies HTTP(S) requests and applies response policies. Tor listeners are the next integration layer.

## Configuration check

Build with `go build .`, then validate with `rotx -config rotx.conf`. The command reads the configuration, included files and identity keys, compiles the routing table and exits. It uses the single global `github.com/coalaura/plain` logger; errors propagate to `main`, where `log.MustFail` handles failure.

```nginx
http {
	header_set X-Content-Type-Options nosniff;

	server {
		# Replace with the lowercase, 56-character v3 identity matching the keys.
		name "<your-onion-name-without-.onion>";
		key_private keys/hs_ed25519_secret_key;
		key_public keys/hs_ed25519_public_key;

		root public;
		index index.html index.htm;
		cache auto;

		location = /health {
			header_set Content-Type text/plain;
			return 200 "ok\n";
		}

		location ^~ /assets/ {
			alias assets;
			cache 30d;
		}

		location /api/ {
			proxy_pass http://localhost:8080/base;
			proxy_buffer off;
		}

		location ~ "^/old/[0-9]{2}$" {
			return 410;
		}
	}
}
```

## Loading and validation

- `config.Load(filename)` reads and compiles a configuration. `config.Compile(source, filename)` accepts bytes, using the filename for diagnostics and relative paths. Results own their data and are safe for concurrent requests.
- `pkg/config/syntax` owns the lexer, streaming parser, include expansion, source diagnostics and syntax tree. `syntax.Load` and `syntax.Parse` return owned `[]syntax.Statement` trees without interpreting directives or reading identity keys. `pkg/config` owns semantic validation, identity verification, inheritance and routing compilation.
- Exactly one `http` block is required, containing at least one `server`. Locations are direct children of servers. Unknown/misplaced directives, wrong argument counts, duplicate singleton directives, conflicting handlers and duplicate identities are errors.
- Each server requires `name`, `key_private` and `key_public`. The onion version/checksum, public key and private key must agree. Supported keys are Tor's native header-bearing Ed25519 files and unencrypted PKCS#8 private/PKIX public Ed25519 PEM files. Bare seeds/raw keys are rejected.
- `include path-or-glob;` inserts tokens at its position, including across block boundaries. Globs are sorted; missing matches, cycles and include nesting beyond 64 files are errors. Relative paths, including `root`, `alias` and keys, are resolved against the file containing that directive.
- Diagnostics retain source filename, line and column. Duplicate declarations report the original location.
- `Config.Identities()` exposes identity names and absolute key paths in declaration order. Key material is validated during compilation; a future Tor runtime rereading those paths must validate the new contents too.

## Routing and inheritance

1. Exact `location = /path` wins.
2. Find the longest plain or `^~` prefix; if that longest prefix is `^~`, use it directly.
3. Otherwise test quoted `~` Go regular expressions in declaration order; first match wins.
4. Fall back to the longest prefix, then the server handler, then 404.

Prefix matching is textual: `/foo` also matches `/foobar`. Requests use the already-decoded `URL.Path`, with repeated slashes and dot segments normalized once and query strings excluded. Escaped percent signs are never decoded a second time. HTTP host lookup requires a configured `.onion` hostname and accepts normal hostname case differences and optional ports.

Locations inherit from their server, never another location. An explicit `root`, `alias`, `proxy_pass` or `return` replaces the inherited handler; only one may appear in a block.

| Directive | Scope | Behavior |
| --- | --- | --- |
| `root path` | server/location | Append the entire normalized request path. |
| `alias path` | server/location | Prefix locations remove their matched prefix; exact locations use the target directly. Server aliases append the whole path, including when inherited. Explicit regex aliases are rejected. |
| `index name ...` | server/location | Replace the inherited index list; default `index.html`. Try these in order, then return 404, with no directory listing. |
| `proxy_pass URL` | location | HTTP(S) origin and optional base path; join that base with the entire normalized request path. Credentials, query strings and fragments are rejected. |
| `proxy_path /path` | location | Replace the entire outgoing path, including the upstream base. Preserve the request query. Requires `proxy_pass`. |
| `proxy_buffer on/off` | location | Buffer the complete response body until the handoff returns; default off. Requires `proxy_pass`. |
| `return status [body]` | location | A standard final HTTP status, with its standard text or a literal custom body. Must be last after include expansion. Explicit bodies are rejected for 204, 205 and 304. |

## Response policies

`header_set`, `header_unset` and `header_add` modify response headers. Names are canonicalized. Operations run in declaration order within HTTP, server, then location scope, after cache processing. Set replaces all values, unset removes them and add appends. This includes generated error responses. Transport framing/connection headers are reserved. Unsetting `Content-Type` or `Date` also suppresses their automatic HTTP generation.

`cache` is allowed at server/location scope. Omitted values inherit; the default is `auto`.

| Value | Effect |
| --- | --- |
| `auto` | Leave cache headers untouched, explicitly cancelling any inherited policy. |
| `off` | `Cache-Control: no-store`. |
| `on` | `Cache-Control: public, max-age=3600`. |
| Positive integer plus `d`, `h`, `m` or `s` | `Cache-Control: public, max-age=N`. Compound/fractional/overflowing durations are rejected. |

Enabled static caching uses file metadata to add `Last-Modified` and a weak size/mtime `ETag`. Custom handlers can supply a content-derived ETag. GET/HEAD conditional requests support `If-None-Match` (including weak comparisons and lists), taking precedence over `If-Modified-Since`; matching responses become bodyless 304s. Proxy validators are left to the upstream. Header directives run last and can override or remove caching headers.

## Runtime handlers

`router.New(compiled, router.Handoffs{})` constructs an `http.Handler` with built-in static and proxy handlers. `Router.Handle` additionally returns handler/write errors; `ServeHTTP` can report these through `Handoffs.Error`, allowing the application to use its global logger. Call `Router.CloseIdleConnections()` when retiring a router. The CLI currently remains a configuration check; it does not start a listener.

- Static GET/HEAD responses include MIME detection, byte ranges, preconditions and configured index lookup. Other methods return 405. Directory URLs redirect to a trailing slash, preserving the query; exact directory aliases serve their index directly. Missing/inaccessible files and directories without an index return 404.
- Static opens use `os.Root` to prevent traversal and symlink escapes beyond the configured root/alias. Relative symlinks inside that boundary work. Exact file aliases use their containing directory as the boundary; exact directory aliases use the directory itself. Only regular files are served.
- HTTP(S) proxying preserves methods, request bodies, query strings, status codes, redirects, encoded bodies and end-to-end response headers. It reuses upstream connections, honors request cancellation, verifies TLS normally and strips hop-by-hop headers. Environment proxy variables are not used. Dial/header timeouts are 30 seconds and TLS handshakes have a 10-second timeout; response bodies may stream indefinitely while the request remains active.
- Upstream `Host` is the configured upstream authority. `X-Forwarded-Host` and `X-Forwarded-Proto` describe the incoming request. Incoming `Forwarded`, `X-Forwarded-For` and `X-Real-IP` are removed; the router does not expose transport peer addresses. Request and response trailers are forwarded except protocol/cache/authentication fields; response trailers also exclude names controlled by configured header operations. CONNECT and protocol upgrades currently return 501.
- Response headers are held until status commitment; `proxy_buffer on` retains the entire response body in memory until completion. Streaming responses flush as upstream chunks arrive. Buffered failures discard the partial response and produce 502 for proxies or 500 for static handlers. Streaming failures propagate through `Handle`; `ServeHTTP` aborts the downstream stream so a truncated response cannot appear successful. `Flush` cannot bypass configured buffering.
- Optional `Handoffs.Proxy` and `Handoffs.Static` replace the built-ins. Proxy receives a `*router.Response`, request and prepared upstream URL. Static receives a response, request and `StaticTarget` with a lexical path and immutable route/index policy; custom file openers must enforce containment and call `Response.SetMetadata` before writing. `Handoffs.Transport` optionally supplies a custom `http.RoundTripper` for the built-in proxy.

## Verification

Use `go test ./...` and `vet ./...`. `go test ./pkg/config -run '^$' -bench '^BenchmarkCompiledMatch$' -benchmem` benchmarks lookup against 1,000 prefix routes. The lookup hot path allocates no memory.
