package config

import (
	"math"
	"strconv"
	"strings"
)

const (
	IdentityEncoding Encoding = iota
	Zstd
	Gzip
	Brotli
)

const (
	CompressCacheOff CompressionCache = iota
	CompressCacheFile
	CompressCacheMemory
)

const (
	TokensAuto ServerTokens = iota
	TokensOff
	TokensFull
	TokensKeep
)

type Encoding uint8

type CompressionCache uint8

type ServerTokens uint8

// CompressionPolicy stores preference order inline; negotiation needs no slices.
type CompressionPolicy struct {
	Count      int
	Algorithms [3]Encoding
	Cache      CompressionCache
}

func (encoding Encoding) String() string {
	switch encoding {
	case Zstd:
		return "zstd"
	case Gzip:
		return "gzip"
	case Brotli:
		return "br"
	}

	return "identity"
}

func (encoding Encoding) Suffix() string {
	switch encoding {
	case Zstd:
		return ".zst"
	case Gzip:
		return ".gz"
	case Brotli:
		return ".br"
	}

	return ""
}

func compileResponsePolicy(route *Route, parsed *scope) error {
	current := parsed.values["compress"]
	if current != nil {
		route.compression.Algorithms = [3]Encoding{}
		route.compression.Count = 0

		for _, argument := range current.Args {
			var encoding Encoding

			switch argument.Value {
			case "off":
				if len(current.Args) != 1 {
					return diagnostic(argument.Position, "compress off cannot be combined with algorithms")
				}

				continue
			case "zstd":
				encoding = Zstd
			case "gzip":
				encoding = Gzip
			case "brotli":
				encoding = Brotli
			default:
				return diagnostic(argument.Position, "unknown compression algorithm %q", argument.Value)
			}

			for index := range route.compression.Count {
				if route.compression.Algorithms[index] == encoding {
					return diagnostic(argument.Position, "duplicate compression algorithm %q", argument.Value)
				}
			}

			route.compression.Algorithms[route.compression.Count] = encoding
			route.compression.Count++
		}
	}

	current = parsed.values["compress_cache"]
	if current != nil {
		switch current.Args[0].Value {
		case "off":
			route.compression.Cache = CompressCacheOff
		case "file":
			route.compression.Cache = CompressCacheFile
		case "memory":
			route.compression.Cache = CompressCacheMemory
		default:
			return diagnostic(current.Position, "compress_cache requires off, file, or memory")
		}
	}

	current = parsed.values["server_tokens"]
	if current != nil {
		switch current.Args[0].Value {
		case "auto":
			route.tokens = TokensAuto
		case "off":
			route.tokens = TokensOff
		case "full":
			route.tokens = TokensFull
		case "keep":
			route.tokens = TokensKeep
		default:
			return diagnostic(current.Position, "server_tokens requires auto, off, full, or keep")
		}
	}

	return nil
}

func parseToggle(current *statement) (bool, error) {
	switch current.Args[0].Value {
	case "on":
		return true, nil
	case "off":
		return false, nil
	}

	return false, diagnostic(current.Position, "%s requires on or off", current.Name)
}

func parseMemoryLimit(current *statement) (int64, error) {
	value := current.Args[0].Value
	multiplier := int64(1)

	if len(value) > 0 {
		switch value[len(value)-1] {
		case 'K', 'k':
			multiplier = 1 << 10
		case 'M', 'm':
			multiplier = 1 << 20
		case 'G', 'g':
			multiplier = 1 << 30
		}
	}

	if multiplier != 1 {
		value = value[:len(value)-1]
	}

	number, err := strconv.ParseInt(value, 10, 64)
	if err != nil || number <= 0 || number > math.MaxInt64/multiplier || strings.Trim(value, "0123456789") != "" {
		return 0, diagnostic(current.Position, "compress_memory_limit requires a positive byte count with optional K, M, or G suffix")
	}

	return number * multiplier, nil
}
