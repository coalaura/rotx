package router

import (
	"io"
	"net/http"
	"strings"

	"github.com/coalaura/rotx/pkg/config"
)

type compressionWriter interface {
	io.WriteCloser
	Flush() error
}

// negotiateEncoding parses directly into fixed slots. Explicit exclusions win
// over wildcards and duplicate tokens; directive order breaks quality ties.
func negotiateEncoding(values []string, policy config.CompressionPolicy) (config.Encoding, bool) {
	if len(values) == 0 {
		return config.IdentityEncoding, true
	}

	qualities := [5]int{-1, -1, -1, -1, -1}

	for _, value := range values {
		for member := range strings.SplitSeq(value, ",") {
			token, parameters, hasParameters := strings.Cut(strings.TrimSpace(member), ";")

			slot := encodingSlot(strings.TrimSpace(token))
			if slot < 0 {
				continue
			}

			quality := 1000

			if hasParameters {
				name, weight, found := strings.Cut(strings.TrimSpace(parameters), "=")
				if !found || !strings.EqualFold(strings.TrimSpace(name), "q") {
					quality = 0
				} else {
					quality = parseQuality(strings.TrimSpace(weight))
				}
			}

			if qualities[slot] < 0 || quality < qualities[slot] {
				qualities[slot] = quality
			}
		}
	}

	var (
		selected config.Encoding
		best     int
	)

	for index := range policy.Count {
		encoding := policy.Algorithms[index]

		quality := qualities[encoding]
		if quality < 0 {
			quality = qualities[4]
		}

		if quality > best {
			selected = encoding
			best = quality
		}
	}

	identity := qualities[0]
	if identity > best {
		return config.IdentityEncoding, true
	}

	if best > 0 {
		return selected, true
	}

	return config.IdentityEncoding, identity > 0 || identity < 0 && qualities[4] != 0
}

func encodingSlot(token string) int {
	switch {
	case strings.EqualFold(token, "identity"):
		return 0
	case strings.EqualFold(token, "zstd"):
		return int(config.Zstd)
	case strings.EqualFold(token, "gzip"):
		return int(config.Gzip)
	case strings.EqualFold(token, "br"):
		return int(config.Brotli)
	case token == "*":
		return 4
	}

	return -1
}

func parseQuality(value string) int {
	if len(value) == 0 || value[0] != '0' && value[0] != '1' {
		return 0
	}

	quality := int(value[0]-'0') * 1000

	if len(value) == 1 {
		return quality
	}

	if value[1] != '.' || len(value) > 5 {
		return 0
	}

	multiplier := 100

	for index := 2; index < len(value); index++ {
		digit := value[index]
		if digit < '0' || digit > '9' || value[0] == '1' && digit != '0' {
			return 0
		}

		quality += int(digit-'0') * multiplier
		multiplier /= 10
	}

	return quality
}

func varyEncoding(headers http.Header) {
	for _, value := range headers.Values("Vary") {
		for token := range strings.SplitSeq(value, ",") {
			token = strings.TrimSpace(token)
			if token == "*" || strings.EqualFold(token, "Accept-Encoding") {
				return
			}
		}
	}

	headers.Add("Vary", "Accept-Encoding")
}

func noTransform(headers http.Header) bool {
	for _, value := range headers.Values("Cache-Control") {
		for token := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "no-transform") {
				return true
			}
		}
	}

	return false
}
