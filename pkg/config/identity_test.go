package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPrivateKeyFormats(t *testing.T) {
	fixture := newIdentityFixture(t)

	identity := Identity{
		Name:           fixture.name,
		PrivateKeyPath: filepath.Join(fixture.directory, "private.pem"),
		PublicKeyPath:  filepath.Join(fixture.directory, "public.pem"),
	}

	expected := sha512.Sum512(fixture.private.Seed())

	expected[0] &= 248
	expected[31] &= 63
	expected[31] |= 64

	private, err := identity.LoadPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(private, expected[:]) {
		t.Fatal("PEM key was not expanded to Tor's scalar and signing prefix")
	}

	clear(private)

	writeFixture(t, identity.PrivateKeyPath, append([]byte(torPrivateHeader), expected[:]...))
	writeFixture(t, identity.PublicKeyPath, append([]byte(torPublicHeader), fixture.public...))

	private, err = identity.LoadPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(private, expected[:]) {
		t.Fatal("native expanded key changed during loading")
	}

	clear(private)
}

func TestLoadPrivateKeyRevalidatesFiles(t *testing.T) {
	fixture := newIdentityFixture(t)

	compiled := compileFixture(t, fixture, fixture.config(""))

	for identity := range compiled.Identities() {
		other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
		expanded := sha512.Sum512(other.Seed())

		expanded[0] &= 248
		expanded[31] &= 63
		expanded[31] |= 64

		writeFixture(t, identity.PrivateKeyPath, append([]byte(torPrivateHeader), expanded[:]...))

		private, err := identity.LoadPrivateKey()
		if err == nil || private != nil || !strings.Contains(err.Error(), "key_private does not match") {
			t.Fatalf("changed private key accepted: %v", err)
		}

		err = os.Remove(identity.PublicKeyPath)
		if err != nil {
			t.Fatal(err)
		}

		private, err = identity.LoadPrivateKey()
		if err == nil || private != nil || !strings.Contains(err.Error(), "key_public") {
			t.Fatalf("missing public key accepted: %v", err)
		}
	}
}

func TestRejectMalformedKeyEncodings(t *testing.T) {
	fixture := newIdentityFixture(t)

	expanded := sha512.Sum512(fixture.private.Seed())

	expanded[0] &= 248
	expanded[31] &= 63
	expanded[31] |= 64

	native := append([]byte(torPrivateHeader), expanded[:]...)

	badScalar := bytes.Clone(native)

	badScalar[len(torPrivateHeader)] |= 1

	badHeader := bytes.Clone(native)

	badHeader[0] = '!'

	der, err := x509.MarshalPKCS8PrivateKey(fixture.private)
	if err != nil {
		t.Fatal(err)
	}

	validPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	wrongType := pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: der})
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: der})

	invalid := [][]byte{
		native[:len(native)-1],
		append(bytes.Clone(native), 0),
		badScalar,
		badHeader,
		fixture.private,
		wrongType,
		encrypted,
		append(bytes.Clone(validPEM), validPEM...),
		append([]byte("junk\n"), validPEM...),
		append(bytes.Clone(validPEM), []byte("junk")...),
		append([]byte("-----BEGIN PRIVATE KEY-----\n!\n-----END PRIVATE KEY-----\n"), validPEM...),
	}

	for index, contents := range invalid {
		_, err := parsePrivateKey(contents)
		if err == nil {
			t.Fatalf("malformed key %d accepted", index)
		}
	}
}

func TestOnionChecksumVersionAndPublicMismatch(t *testing.T) {
	fixture := newIdentityFixture(t)

	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)

	decoded, err := encoding.DecodeString(strings.ToUpper(fixture.name))
	if err != nil {
		t.Fatal(err)
	}

	decoded[32] ^= 1

	_, err = onionPublicKey(strings.ToLower(encoding.EncodeToString(decoded)))
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("bad checksum: %v", err)
	}

	decoded[34] = 4

	_, err = onionPublicKey(strings.ToLower(encoding.EncodeToString(decoded)))
	if err == nil || !strings.Contains(err.Error(), "v3") {
		t.Fatalf("bad version: %v", err)
	}

	public := bytes.Clone(fixture.public)

	public[0] ^= 1

	writeFixture(t, filepath.Join(fixture.directory, "public.pem"), append([]byte(torPublicHeader), public...))

	_, err = Compile([]byte(fixture.config("")), filepath.Join(fixture.directory, "rotx.conf"))
	if err == nil || !strings.Contains(err.Error(), "key_public does not match") {
		t.Fatalf("bad public identity: %v", err)
	}
}
