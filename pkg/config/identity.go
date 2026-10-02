package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha3"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"filippo.io/edwards25519"
)

const (
	torPrivateHeader = "== ed25519v1-secret: type0 ==\x00\x00\x00"
	torPublicHeader  = "== ed25519v1-public: type0 ==\x00\x00\x00"
)

func validateIdentity(name, privatePath, publicPath string) error {
	public, err := onionPublicKey(name)
	if err != nil {
		return err
	}

	publicFile, err := os.ReadFile(publicPath)
	if err != nil {
		return fmt.Errorf("key_public: %w", err)
	}

	loaded, err := parsePublicKey(publicFile)
	if err != nil {
		return fmt.Errorf("key_public: %w", err)
	}

	if !bytes.Equal(public, loaded) {
		return fmt.Errorf("key_public does not match onion name")
	}

	privateFile, err := os.ReadFile(privatePath)
	if err != nil {
		return fmt.Errorf("key_private: %w", err)
	}

	defer clear(privateFile)

	derived, err := privatePublicKey(privateFile)
	if err != nil {
		return fmt.Errorf("key_private: %w", err)
	}

	if subtle.ConstantTimeCompare(derived, public) != 1 {
		return fmt.Errorf("key_private does not match key_public and onion name")
	}

	return nil
}

func onionPublicKey(name string) ([]byte, error) {
	if len(name) != 56 || strings.Trim(name, "abcdefghijklmnopqrstuvwxyz234567") != "" {
		return nil, fmt.Errorf("name must be a lowercase v3 onion address without .onion")
	}

	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(name))
	if err != nil || len(decoded) != 35 || decoded[34] != 3 {
		return nil, fmt.Errorf("invalid v3 onion identity")
	}

	var checksumInput [48]byte

	copy(checksumInput[:], ".onion checksum")
	copy(checksumInput[15:], decoded[:32])

	checksumInput[47] = 3

	checksum := sha3.Sum256(checksumInput[:])
	if !bytes.Equal(checksum[:2], decoded[32:34]) {
		return nil, fmt.Errorf("invalid onion checksum")
	}

	return decoded[:32], nil
}

func parsePublicKey(contents []byte) ([]byte, error) {
	if len(contents) == len(torPublicHeader)+ed25519.PublicKeySize && bytes.HasPrefix(contents, []byte(torPublicHeader)) {
		return contents[len(torPublicHeader):], nil
	}

	block, err := decodePEM(contents, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	public, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key must be Ed25519")
	}

	return public, nil
}

func privatePublicKey(contents []byte) ([]byte, error) {
	if len(contents) == len(torPrivateHeader)+64 && bytes.HasPrefix(contents, []byte(torPrivateHeader)) {
		expanded := contents[len(torPrivateHeader):]
		if expanded[0]&7 != 0 || expanded[31]&192 != 64 {
			return nil, fmt.Errorf("invalid expanded Ed25519 scalar")
		}

		var scalar edwards25519.Scalar

		_, err := scalar.SetBytesWithClamping(expanded[:32])
		if err != nil {
			return nil, err
		}

		var point edwards25519.Point

		return point.ScalarBaseMult(&scalar).Bytes(), nil
	}

	block, err := decodePEM(contents, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}

	defer clear(block.Bytes)

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key must be Ed25519")
	}

	defer clear(private)

	return private.Public().(ed25519.PublicKey), nil
}

func decodePEM(contents []byte, kind string) (*pem.Block, error) {
	contents = bytes.TrimSpace(contents)
	if !bytes.HasPrefix(contents, []byte("-----BEGIN "+kind+"-----")) || bytes.Count(contents, []byte("-----BEGIN ")) != 1 {
		return nil, fmt.Errorf("expected Tor native key or unencrypted %s PEM", kind)
	}

	block, rest := pem.Decode(contents)
	if block == nil || block.Type != kind || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("expected exactly one unencrypted %s PEM block", kind)
	}

	return block, nil
}
