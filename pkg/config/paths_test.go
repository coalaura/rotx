package config

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type staticPathCase struct {
	name   string
	body   string
	target string
	valid  bool
}

func TestStaticPathValidation(t *testing.T) {
	fixture := newIdentityFixture(t)

	writeFixture(t, filepath.Join(fixture.directory, "file.txt"), []byte("file"))

	cases := []staticPathCase{
		{name: "missing root", body: `root missing;`, target: "missing"},
		{name: "file root", body: `root file.txt;`, target: "file.txt"},
		{name: "missing server alias", body: `alias missing;`, target: "missing"},
		{name: "file server alias", body: `alias file.txt;`, target: "file.txt"},
		{name: "missing prefix alias", body: `location /assets/ { alias missing; }`, target: "missing"},
		{name: "file prefix alias", body: `location /assets/ { alias file.txt; }`, target: "file.txt"},
		{name: "missing exact alias", body: `location = /file { alias missing; }`, target: "missing"},
		{name: "file location root", body: `location = /file { root file.txt; }`, target: "file.txt"},
		{name: "unused invalid root", body: `root missing; location / { return 200; }`, target: "missing"},
		{name: "directory root", body: `root .; index absent.html;`, valid: true},
		{name: "directory server alias", body: `alias .;`, valid: true},
		{name: "directory prefix alias", body: `location /assets/ { alias .; }`, valid: true},
		{name: "file exact alias", body: `location = /file { alias file.txt; }`, valid: true},
		{name: "directory exact alias", body: `location = /directory { alias .; }`, valid: true},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile([]byte(fixture.config(test.body)), filepath.Join(fixture.directory, "rotx.conf"))

			if test.valid {
				if err != nil {
					t.Fatal(err)
				}

				return
			}

			var failure *Diagnostic

			expectedPath := strconv.Quote(filepath.Join(fixture.directory, test.target))
			if !errors.As(err, &failure) || failure.Position.Line == 0 || !strings.Contains(failure.Message, expectedPath) {
				t.Fatalf("expected a source diagnostic with the resolved path, got %v", err)
			}
		})
	}
}

func TestStaticPathValidationIncludedSource(t *testing.T) {
	fixture := newIdentityFixture(t)

	directory := filepath.Join(fixture.directory, "parts")

	err := os.Mkdir(directory, 0700)
	if err != nil {
		t.Fatal(err)
	}

	filename := filepath.Join(directory, "static.conf")

	writeFixture(t, filename, []byte("\nroot missing;"))

	_, err = Compile([]byte(fixture.config(`include parts/static.conf;`)), filepath.Join(fixture.directory, "rotx.conf"))

	var failure *Diagnostic

	if !errors.As(err, &failure) || failure.Position.File != filename || failure.Position.Line != 2 || !strings.Contains(failure.Message, filepath.Join(directory, "missing")) {
		t.Fatalf("expected included directive and resolved path, got %v", err)
	}
}
