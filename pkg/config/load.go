// Package config validates configuration syntax and compiles immutable routing policies.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/coalaura/rotx/pkg/config/syntax"
)

type Position = syntax.Position

type Diagnostic = syntax.Diagnostic

type statement = syntax.Statement

// Load reads, validates, and compiles a configuration, including its key files
// and configured static roots and aliases.
func Load(filename string) (*Config, error) {
	source, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return Compile(source, filename)
}

// Compile owns its result; source may be reused after this call. filename sets
// diagnostics and the base directory for includes and filesystem directives.
func Compile(source []byte, filename string) (*Config, error) {
	absolute, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}

	statements, err := syntax.Parse(source, absolute)
	if err != nil {
		return nil, err
	}

	return compileConfig(statements, Position{File: absolute, Line: 1, Column: 1})
}

func resolveFile(filename, value string) string {
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}

	return filepath.Join(filepath.Dir(filename), value)
}

func diagnostic(position Position, format string, args ...any) error {
	return &Diagnostic{Position: position, Message: fmt.Sprintf(format, args...)}
}
