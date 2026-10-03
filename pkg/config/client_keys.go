package config

import (
	"crypto/ecdh"
	"encoding/base32"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func loadClientKeys(directives []*statement) ([]string, error) {
	keys := make([]string, 0, len(directives))
	seen := make(map[string]struct{}, len(directives))

	for _, current := range directives {
		value := current.Args[0].Value
		if value == "" || strings.ContainsRune(value, 0) {
			return nil, diagnostic(current.Position, "empty or invalid client key path")
		}

		path := resolveFile(current.Position.File, value)

		paths := []string{path}

		if current.Name == "client_keys" {
			entries, err := os.ReadDir(path)
			if err != nil {
				return nil, diagnostic(current.Position, "read client key directory: %v", err)
			}

			paths = make([]string, 0, len(entries))

			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".auth") {
					paths = append(paths, filepath.Join(path, entry.Name()))
				}
			}

			if len(paths) == 0 {
				return nil, diagnostic(current.Position, "client key directory contains no .auth files")
			}
		}

		for _, filename := range paths {
			key, err := loadClientKey(filename)
			if err != nil {
				return nil, diagnostic(current.Position, "client key %q: %v", filename, err)
			}

			if _, exists := seen[key]; exists {
				continue
			}

			seen[key] = struct{}{}
			keys = append(keys, key)
		}
	}

	return keys, nil
}

func loadClientKey(path string) (string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	key, found := strings.CutPrefix(strings.TrimSpace(string(contents)), "descriptor:x25519:")
	if !found || len(key) != 52 {
		return "", fmt.Errorf("expected descriptor:x25519:<52-character base32 public key>")
	}

	key = strings.ToUpper(key)
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)

	decoded, err := encoding.DecodeString(key)
	if err != nil || len(decoded) != 32 || encoding.EncodeToString(decoded) != key {
		return "", fmt.Errorf("invalid X25519 public key encoding")
	}

	public, err := ecdh.X25519().NewPublicKey(decoded)
	if err != nil {
		return "", err
	}

	// Reject low-order public keys which cannot establish a shared secret.
	scalar := [32]byte{1}

	private, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		return "", err
	}

	_, err = private.ECDH(public)
	if err != nil {
		return "", fmt.Errorf("invalid X25519 public key: %w", err)
	}

	return key, nil
}
