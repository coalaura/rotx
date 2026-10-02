package syntax

import (
	"bytes"
	"strings"
	"testing"
)

const sampleConfig = `# a complete config
key value1 value2 value3;
key2 value;
block {
	key value;
	block2 thing {
		key value1 value2;
		key "string \" escaped";
		key 1234;
	}
}
server {
	listen [::]:443 ssl;
	location @backend {
		proxy_pass https://user:pass@example.com:8443/a?b=c#fragment;
		root /var/www/${host}/$uri;
		unix unix:/run/backend.sock;
	}
}
`

type lexerCase struct {
	source string
	kind   Kind
	value  string
}

type eventExpectation struct {
	kind  EventKind
	depth int
	name  string
	args  []string
}

type parserCase struct {
	source string
	events []eventExpectation
}

type errorCase struct {
	source   string
	code     ErrorCode
	offset   int
	capacity int
}

var benchmarkCount int

func TestLexerValues(t *testing.T) {
	cases := []lexerCase{
		{source: "1234", kind: Number, value: "1234"},
		{source: "-12.5", kind: Ident, value: "-12.5"},
		{source: "https://user:pass@example.com:8443/a?b=c#fragment", kind: Ident, value: "https://user:pass@example.com:8443/a?b=c#fragment"},
		{source: "[2001:db8::1]:443", kind: Ident, value: "[2001:db8::1]:443"},
		{source: "unix:/run/backend.sock", kind: Ident, value: "unix:/run/backend.sock"},
		{source: "@backend", kind: Ident, value: "@backend"},
		{source: "/var/www/${host}/$uri", kind: Ident, value: "/var/www/${host}/$uri"},
		{source: "${host}${port}", kind: Ident, value: "${host}${port}"},
		{source: "路径/é", kind: Ident, value: "路径/é"},
		{source: `"string \" escaped"`, kind: String, value: `string " escaped`},
		{source: `'single \' quote'`, kind: String, value: "single ' quote"},
		{source: `""`, kind: String, value: ""},
		{source: `''`, kind: String, value: ""},
		{source: `prefix" with spaces"' and more'`, kind: String, value: "prefix with spaces and more"},
		{source: `"# { } ; ' ${host}"`, kind: String, value: "# { } ; ' ${host}"},
		{source: `"line\nreturn\rtab\tbackslash\\"`, kind: String, value: "line\nreturn\rtab\tbackslash\\"},
		{source: `"^\d{2}\.txt$"`, kind: String, value: `^\d{2}\.txt$`},
		{source: `path\ with\ spaces\;\{\}\#\$`, kind: String, value: "path with spaces;{}#$"},
		{source: `escaped\"quote`, kind: String, value: `escaped"quote`},
		{source: `C:\\nginx\\conf`, kind: String, value: `C:\nginx\conf`},
		{source: "\"multi\nline\"", kind: String, value: "multi\nline"},
	}

	for index := range cases {
		testCase := &cases[index]

		t.Run(testCase.source, func(t *testing.T) {
			source := []byte(testCase.source)

			var lexer Lexer

			lexer.Reset(source)

			token := lexer.Next()
			if token.Kind != testCase.kind || token.Start != 0 || token.End != len(source) {
				t.Fatalf("token = %+v, want kind %d covering input", token, testCase.kind)
			}

			if !bytes.Equal(token.Text(source), source) {
				t.Fatal("raw text differs from input")
			}

			destination := make([]byte, 0, len(source)+7)

			destination = append(destination, "prefix:"...)

			value := token.AppendValue(destination, source)
			if string(value[7:]) != testCase.value {
				t.Fatalf("decoded value = %q, want %q", value[7:], testCase.value)
			}

			end := lexer.Next()
			if end.Kind != EOF || end.Start != len(source) || lexer.Err().Code != NoError {
				t.Fatalf("end = %+v, error = %+v", end, lexer.Err())
			}
		})
	}
}

func TestLexerBoundaries(t *testing.T) {
	source := []byte(" \t\r\n\v\f# comment\r\nkey value;block{key;}# trailing")
	expected := []Kind{Comment, Ident, Ident, Semicolon, Ident, LBrace, Ident, Semicolon, RBrace, Comment, EOF}

	var lexer Lexer

	lexer.Reset(source)

	for _, kind := range expected {
		token := lexer.Next()
		if token.Kind != kind {
			t.Fatalf("token = %+v, want kind %d", token, kind)
		}
	}

	end := lexer.Next()
	if end.Kind != EOF || lexer.Err().Code != NoError {
		t.Fatalf("end = %+v, error = %+v", end, lexer.Err())
	}
}

func TestParserEvents(t *testing.T) {
	cases := []parserCase{
		{source: "", events: nil},
		{source: "# only a comment", events: nil},
		{
			source: "key; key2 one two; block thing { nested { key 1234; } }",
			events: []eventExpectation{
				{kind: Directive, depth: 0, name: "key", args: nil},
				{kind: Directive, depth: 0, name: "key2", args: []string{"one", "two"}},
				{kind: BlockStart, depth: 0, name: "block", args: []string{"thing"}},
				{kind: BlockStart, depth: 1, name: "nested", args: nil},
				{kind: Directive, depth: 2, name: "key", args: []string{"1234"}},
				{kind: BlockEnd, depth: 1, name: "", args: nil},
				{kind: BlockEnd, depth: 0, name: "", args: nil},
			},
		},
		{
			source: "key # between name and arguments\n value # before terminator\n; block # before brace\n{ # inside\n }",
			events: []eventExpectation{
				{kind: Directive, depth: 0, name: "key", args: []string{"value"}},
				{kind: BlockStart, depth: 0, name: "block", args: nil},
				{kind: BlockEnd, depth: 0, name: "", args: nil},
			},
		},
		{
			source: `key "" 'a b' path\ with\ spaces;`,
			events: []eventExpectation{
				{kind: Directive, depth: 0, name: "key", args: []string{`""`, `'a b'`, `path\ with\ spaces`}},
			},
		},
	}

	for index := range cases {
		testCase := &cases[index]

		t.Run(testCase.source, func(t *testing.T) {
			source := []byte(testCase.source)

			var (
				arguments [8]Token
				parser    Parser
			)

			parser.Reset(source)

			var previousEnd int

			for eventIndex := range testCase.events {
				expected := &testCase.events[eventIndex]

				event, ok := parser.Next(arguments[:])
				if !ok {
					t.Fatalf("missing event %d: %+v", eventIndex, parser.Err())
				}

				if event.Kind != expected.kind || event.Depth != expected.depth || string(event.Name.Text(source)) != expected.name || len(event.Args) != len(expected.args) {
					t.Fatalf("event %d = %+v, want %+v", eventIndex, event, expected)
				}

				if event.Start < previousEnd || event.End <= event.Start || event.End > len(source) {
					t.Fatalf("invalid event span: %+v", event)
				}

				terminator := source[event.End-1]
				if event.Kind == Directive && terminator != ';' || event.Kind == BlockStart && terminator != '{' || event.Kind == BlockEnd && terminator != '}' {
					t.Fatalf("incorrect terminator for %+v", event)
				}

				previousEnd = event.End

				for argumentIndex, argument := range event.Args {
					if string(argument.Text(source)) != expected.args[argumentIndex] {
						t.Fatalf("argument %d = %q, want %q", argumentIndex, argument.Text(source), expected.args[argumentIndex])
					}
				}
			}

			_, ok := parser.Next(arguments[:])
			if ok || parser.Err().Code != NoError {
				t.Fatalf("unexpected final event or error: %+v", parser.Err())
			}

			_, ok = parser.Next(arguments[:])
			if ok {
				t.Fatal("parser resumed after EOF")
			}
		})
	}
}

func TestParserSample(t *testing.T) {
	source := []byte(sampleConfig)

	var (
		arguments [8]Token
		parser    Parser
	)

	parser.Reset(source)

	var events int

	for {
		_, ok := parser.Next(arguments[:])
		if !ok {
			break
		}

		events++
	}

	if events != 18 || parser.Err().Code != NoError {
		t.Fatalf("events = %d, error = %+v", events, parser.Err())
	}
}

func TestParserErrors(t *testing.T) {
	cases := []errorCase{
		{source: ";", code: UnexpectedSemicolon, offset: 0, capacity: 8},
		{source: "{", code: UnexpectedBlockStart, offset: 0, capacity: 8},
		{source: "}", code: UnexpectedBlockEnd, offset: 0, capacity: 8},
		{source: "key", code: MissingTerminator, offset: 3, capacity: 8},
		{source: "block {", code: UnclosedBlock, offset: 7, capacity: 8},
		{source: "block { key value }", code: MissingTerminator, offset: 18, capacity: 8},
		{source: "key \"abc", code: UnterminatedQuote, offset: 4, capacity: 8},
		{source: "key 'abc", code: UnterminatedQuote, offset: 4, capacity: 8},
		{source: "key abc\\", code: UnterminatedEscape, offset: 7, capacity: 8},
		{source: "key \"abc\\", code: UnterminatedEscape, offset: 8, capacity: 8},
		{source: "key ${name;", code: UnterminatedVariable, offset: 5, capacity: 8},
		{source: "key ${name", code: UnterminatedVariable, offset: 5, capacity: 8},
		{source: "key \x00;", code: UnexpectedNUL, offset: 4, capacity: 8},
		{source: "# \x00", code: UnexpectedNUL, offset: 2, capacity: 8},
		{source: "key \"\x00\";", code: UnexpectedNUL, offset: 5, capacity: 8},
		{source: "key \\\x00;", code: UnexpectedNUL, offset: 5, capacity: 8},
		{source: "key \"\\\x00\";", code: UnexpectedNUL, offset: 6, capacity: 8},
		{source: "key ${\x00};", code: UnexpectedNUL, offset: 6, capacity: 8},
		{source: "key one two;", code: ArgumentCapacity, offset: 8, capacity: 1},
		{source: "key one;", code: ArgumentCapacity, offset: 4, capacity: 0},
	}

	for index := range cases {
		testCase := &cases[index]

		t.Run(testCase.source, func(t *testing.T) {
			var (
				arguments [8]Token
				parser    Parser
			)

			parser.Reset([]byte(testCase.source))

			for {
				_, ok := parser.Next(arguments[:testCase.capacity:testCase.capacity])
				if !ok {
					break
				}
			}

			err := parser.Err()
			if err.Code != testCase.code || err.Offset != testCase.offset || err.Error() == "" {
				t.Fatalf("error = %+v, want code %d at %d", err, testCase.code, testCase.offset)
			}

			_, ok := parser.Next(arguments[:])
			if ok || parser.Err() != err {
				t.Fatal("parser did not preserve terminal error")
			}

			parser.Reset([]byte("valid;"))

			_, ok = parser.Next(nil)
			if !ok || parser.Err().Code != NoError {
				t.Fatal("Reset did not clear error")
			}
		})
	}
}

func TestLexerErrorReset(t *testing.T) {
	var lexer Lexer

	lexer.Reset([]byte(`"unfinished`))

	token := lexer.Next()
	if token.Kind != Illegal || lexer.Err().Code != UnterminatedQuote {
		t.Fatalf("token = %+v, error = %+v", token, lexer.Err())
	}

	token = lexer.Next()
	if token.Kind != EOF {
		t.Fatal("lexer did not stop after error")
	}

	lexer.Reset([]byte("1234"))

	token = lexer.Next()
	if token.Kind != Number || lexer.Err().Code != NoError {
		t.Fatal("Reset did not clear error")
	}
}

func TestParserDeepNesting(t *testing.T) {
	source := []byte(strings.Repeat("block {", 10000) + strings.Repeat("}", 10000))

	var parser Parser

	parser.Reset(source)

	var events int

	for {
		event, ok := parser.Next(nil)
		if !ok {
			break
		}

		if event.Depth < 0 || event.Depth >= 10000 {
			t.Fatalf("invalid depth %d", event.Depth)
		}

		events++
	}

	if events != 20000 || parser.Err().Code != NoError {
		t.Fatalf("events = %d, error = %+v", events, parser.Err())
	}
}

func TestZeroAllocations(t *testing.T) {
	source := []byte(sampleConfig)
	invalid := []byte(`key "unfinished`)

	allocations := testing.AllocsPerRun(100, func() {
		var (
			arguments [8]Token
			parser    Parser
		)

		parser.Reset(source)

		for {
			_, ok := parser.Next(arguments[:])
			if !ok {
				break
			}
		}

		if parser.Err().Code != NoError {
			panic("unexpected parse error")
		}

		parser.Reset(invalid)
		parser.Next(arguments[:])

		if parser.Err().Code != UnterminatedQuote {
			panic("missing parse error")
		}

		var (
			lexer   Lexer
			decoded [128]byte
		)

		lexer.Reset(source)

		for {
			token := lexer.Next()
			if token.Kind == EOF {
				break
			}

			token.AppendValue(decoded[:0], source)
		}
	})

	if allocations != 0 {
		t.Fatalf("allocations = %g, want zero", allocations)
	}
}

func BenchmarkLexer(b *testing.B) {
	source := []byte(sampleConfig)

	var (
		lexer Lexer
		count int
	)

	b.SetBytes(int64(len(source)))
	b.ReportAllocs()

	for b.Loop() {
		lexer.Reset(source)

		for {
			token := lexer.Next()
			if token.Kind == EOF {
				break
			}

			count++
		}
	}

	benchmarkCount = count
}

func BenchmarkParser(b *testing.B) {
	source := []byte(sampleConfig)

	var (
		arguments [8]Token
		parser    Parser
		count     int
	)

	b.SetBytes(int64(len(source)))
	b.ReportAllocs()

	for b.Loop() {
		parser.Reset(source)

		for {
			_, ok := parser.Next(arguments[:])
			if !ok {
				break
			}

			count++
		}
	}

	if parser.Err().Code != NoError {
		b.Fatal(parser.Err())
	}

	benchmarkCount = count
}

func BenchmarkAppendValue(b *testing.B) {
	source := []byte(`"string \" escaped with \n and \t and \\"`)

	var (
		lexer Lexer
		count int
	)

	lexer.Reset(source)

	token := lexer.Next()

	var destination [128]byte

	b.SetBytes(int64(len(source)))
	b.ReportAllocs()

	for b.Loop() {
		value := token.AppendValue(destination[:0], source)
		count += len(value)
	}

	benchmarkCount = count
}

func FuzzParser(f *testing.F) {
	f.Add([]byte(sampleConfig))
	f.Add([]byte(`key ""; block ${name} { key path\ with\ spaces; }`))
	f.Add([]byte("key \x00;"))
	f.Add([]byte("block {"))

	f.Fuzz(func(t *testing.T, source []byte) {
		var (
			arguments [16]Token
			parser    Parser
		)

		parser.Reset(source)

		var previousEnd int

		for {
			event, ok := parser.Next(arguments[:])
			if !ok {
				break
			}

			if event.Start < previousEnd || event.End <= event.Start || event.End > len(source) || event.Depth < 0 {
				t.Fatalf("invalid event: %+v", event)
			}

			previousEnd = event.End

			checkToken(t, source, event.Name)

			for _, token := range event.Args {
				checkToken(t, source, token)
			}
		}

		err := parser.Err()
		if err.Offset < 0 || err.Offset > len(source) {
			t.Fatalf("invalid error offset: %+v", err)
		}
	})
}

func checkToken(t *testing.T, source []byte, token Token) {
	t.Helper()

	if token.Start < 0 || token.End < token.Start || token.End > len(source) {
		t.Fatalf("invalid token: %+v", token)
	}

	destination := make([]byte, 0, token.End-token.Start)

	decoded := token.AppendValue(destination, source)
	if len(decoded) > token.End-token.Start {
		t.Fatalf("decoded value grew: %+v", token)
	}
}
