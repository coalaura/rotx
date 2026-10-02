package config

const (
	Illegal Kind = iota
	EOF
	Comment

	Ident
	Number
	String

	LBrace
	RBrace

	Semicolon
)

// Ident includes arbitrary bare values such as URLs, addresses, paths and variables.
// Number denotes only an unquoted sequence of decimal digits; no conversion is done.
// String denotes a token containing quoting or escaping.
type Kind uint8

type Token struct {
	Start int
	End   int
	Kind  Kind
}

// Text returns the raw source view, including any quotes and escape sequences.
func (t Token) Text(source []byte) []byte {
	return source[t.Start:t.End]
}

// AppendValue removes quotes and decodes escapes into destination. Providing room
// for End-Start bytes guarantees no allocation. Unknown escapes retain their slash,
// so regular expressions such as \d are preserved. Variables are not expanded.
func (t Token) AppendValue(destination []byte, source []byte) []byte {
	raw := t.Text(source)

	if t.Kind != String {
		return append(destination, raw...)
	}

	var quote byte

	for cursor := 0; cursor < len(raw); cursor++ {
		character := raw[cursor]
		if character == '\\' && cursor+1 < len(raw) {
			cursor++
			character = raw[cursor]

			switch character {
			case 'n':
				character = '\n'
			case 'r':
				character = '\r'
			case 't':
				character = '\t'
			case '\\', '\'', '"', ' ', '\t', '\n', '\r', '\v', '\f', ';', '{', '}', '#', '$':
			default:
				destination = append(destination, '\\')
			}

			destination = append(destination, character)

			continue
		}

		if character == quote {
			quote = 0

			continue
		}

		if quote == 0 && (character == '\'' || character == '"') {
			quote = character

			continue
		}

		destination = append(destination, character)
	}

	return destination
}
