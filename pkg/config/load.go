package config

import (
	"fmt"
	"os"
	"path/filepath"
)

const maxIncludeDepth = 64

type Position struct {
	File   string
	Line   int
	Column int
}

type Diagnostic struct {
	Position Position
	Message  string
}

type sourceToken struct {
	value    string
	position Position
	kind     Kind
	quoted   bool
}

type statement struct {
	name     string
	args     []sourceToken
	children []statement
	position Position
	block    bool
}

type loader struct {
	active   map[string]bool
	tokens   []sourceToken
	boundary bool
}

func (p Position) String() string {
	return fmt.Sprintf("%s:%d:%d", p.File, p.Line, p.Column)
}

func (d *Diagnostic) Error() string {
	return d.Position.String() + ": " + d.Message
}

func (l *loader) expand(filename string, source []byte, depth int) error {
	if depth >= maxIncludeDepth {
		return fmt.Errorf("%s: include depth exceeds %d", filename, maxIncludeDepth)
	}

	canonical, err := filepath.EvalSymlinks(filename)
	if err != nil {
		canonical = filename
	}

	if l.active[canonical] {
		return fmt.Errorf("%s: include cycle", filename)
	}

	l.active[canonical] = true
	defer delete(l.active, canonical)

	var lexer Lexer

	lexer.Reset(source)

	line := 1
	column := 1
	offset := 0

	var decoded []byte

	for {
		token := lexer.Next()

		for offset < token.Start {
			if source[offset] == '\n' {
				line++

				column = 1
			} else {
				column++
			}

			offset++
		}

		position := Position{File: filename, Line: line, Column: column}

		if token.Kind == Illegal {
			return diagnostic(position, "%s", lexer.Err().Error())
		}

		if token.Kind == EOF {
			return nil
		}

		if token.Kind == Comment {
			continue
		}

		decoded = token.AppendValue(decoded[:0], source)

		value := string(decoded)
		if l.boundary && value == "include" && token.Kind == Ident {
			argument := nextContentToken(&lexer)
			terminator := nextContentToken(&lexer)

			if !valueToken(argument.Kind) || terminator.Kind != Semicolon {
				return diagnostic(position, "include requires one path and a semicolon")
			}

			decoded = argument.AppendValue(decoded[:0], source)
			pattern := resolveFile(filename, string(decoded))

			matches, err := filepath.Glob(pattern)
			if err != nil {
				return diagnostic(position, "invalid include pattern: %v", err)
			}

			if len(matches) == 0 {
				return diagnostic(position, "include %q matched no files", pattern)
			}

			for _, match := range matches {
				contents, err := os.ReadFile(match)
				if err != nil {
					return diagnostic(position, "include: %v", err)
				}

				err = l.expand(match, contents, depth+1)
				if err != nil {
					return diagnostic(position, "include: %v", err)
				}
			}

			continue
		}

		raw := token.Text(source)

		quoted := len(raw) >= 2 && (raw[0] == '"' || raw[0] == '\'') && raw[len(raw)-1] == raw[0]

		l.tokens = append(l.tokens, sourceToken{value: value, position: position, kind: token.Kind, quoted: quoted})
		l.boundary = token.Kind == Semicolon || token.Kind == LBrace || token.Kind == RBrace
	}
}

// Load reads, validates, and compiles a configuration, including its key files.
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

	loader := loader{active: make(map[string]bool), boundary: true}

	err = loader.expand(absolute, source, 0)
	if err != nil {
		return nil, err
	}

	var cursor int

	statements, err := parseStatements(loader.tokens, &cursor, 0)
	if err != nil {
		return nil, err
	}

	return compileConfig(statements, Position{File: absolute, Line: 1, Column: 1})
}

func parseStatements(tokens []sourceToken, cursor *int, depth int) ([]statement, error) {
	var statements []statement

	for *cursor < len(tokens) {
		name := tokens[*cursor]
		*cursor++

		if name.kind == RBrace && depth > 0 {
			return statements, nil
		}

		if name.kind != Ident {
			return nil, diagnostic(name.position, "expected directive or block name")
		}

		current := statement{name: name.value, position: name.position}

		for *cursor < len(tokens) && valueToken(tokens[*cursor].kind) {
			current.args = append(current.args, tokens[*cursor])
			*cursor++
		}

		if *cursor == len(tokens) {
			return nil, diagnostic(name.position, "expected semicolon or opening brace")
		}

		terminator := tokens[*cursor]
		*cursor++

		switch terminator.kind {
		case LBrace:
			if depth >= 3 {
				return nil, diagnostic(name.position, "nested blocks are not allowed here")
			}

			children, err := parseStatements(tokens, cursor, depth+1)
			if err != nil {
				return nil, err
			}

			current.block = true
			current.children = children
		case Semicolon:
		default:
			return nil, diagnostic(terminator.position, "expected semicolon or opening brace")
		}

		statements = append(statements, current)
	}

	if depth > 0 {
		return nil, diagnostic(tokens[len(tokens)-1].position, "unclosed block")
	}

	return statements, nil
}

func nextContentToken(lexer *Lexer) Token {
	for {
		token := lexer.Next()
		if token.Kind != Comment {
			return token
		}
	}
}

func valueToken(kind Kind) bool {
	return kind == Ident || kind == String || kind == Number
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
