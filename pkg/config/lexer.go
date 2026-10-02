package config

// Lexer scans source without copying it. Tokens borrow source until it is changed.
// A Lexer is ready to use after Reset.
type Lexer struct {
	source []byte
	cursor int
	err    Error
}

func (l *Lexer) Reset(source []byte) {
	l.source = source
	l.cursor = 0
	l.err = Error{}
}

// Err returns a value rather than boxing an error, keeping failure paths allocation-free.
func (l *Lexer) Err() Error {
	return l.err
}

// Next returns comments as tokens. After an Illegal token, subsequent calls return EOF.
func (l *Lexer) Next() Token {
	if l.err.Code != NoError {
		return Token{Start: l.cursor, End: l.cursor, Kind: EOF}
	}

	for l.cursor < len(l.source) && isSpace(l.source[l.cursor]) {
		l.cursor++
	}

	start := l.cursor
	if start == len(l.source) {
		return Token{Start: start, End: start, Kind: EOF}
	}

	character := l.source[start]

	switch character {
	case '{':
		l.cursor++

		return Token{Start: start, End: l.cursor, Kind: LBrace}
	case '}':
		l.cursor++

		return Token{Start: start, End: l.cursor, Kind: RBrace}
	case ';':
		l.cursor++

		return Token{Start: start, End: l.cursor, Kind: Semicolon}
	case '#':
		for l.cursor < len(l.source) && l.source[l.cursor] != '\n' {
			if l.source[l.cursor] == 0 {
				return l.fail(UnexpectedNUL, l.cursor, start)
			}

			l.cursor++
		}

		return Token{Start: start, End: l.cursor, Kind: Comment}
	}

	number := true
	quoted := false

	for l.cursor < len(l.source) {
		character = l.source[l.cursor]
		if isSpace(character) || character == ';' || character == '{' || character == '}' {
			break
		}

		switch character {
		case 0:
			return l.fail(UnexpectedNUL, l.cursor, start)
		case '\\':
			number = false
			quoted = true

			escape := l.cursor

			l.cursor++
			if l.cursor == len(l.source) {
				return l.fail(UnterminatedEscape, escape, start)
			}

			if l.source[l.cursor] == 0 {
				return l.fail(UnexpectedNUL, l.cursor, start)
			}

			l.cursor++
		case '\'', '"':
			number = false
			quoted = true

			quote := character
			opening := l.cursor

			l.cursor++

			for l.cursor < len(l.source) && l.source[l.cursor] != quote {
				character = l.source[l.cursor]
				if character == 0 {
					return l.fail(UnexpectedNUL, l.cursor, start)
				}

				if character == '\\' {
					escape := l.cursor

					l.cursor++
					if l.cursor == len(l.source) {
						return l.fail(UnterminatedEscape, escape, start)
					}

					if l.source[l.cursor] == 0 {
						return l.fail(UnexpectedNUL, l.cursor, start)
					}
				}

				l.cursor++
			}

			if l.cursor == len(l.source) {
				return l.fail(UnterminatedQuote, opening, start)
			}

			l.cursor++
		case '$':
			number = false

			l.cursor++
			if l.cursor < len(l.source) && l.source[l.cursor] == '{' {
				opening := l.cursor
				l.cursor++

				for l.cursor < len(l.source) && l.source[l.cursor] != '}' {
					character = l.source[l.cursor]
					if character == 0 {
						return l.fail(UnexpectedNUL, l.cursor, start)
					}

					if isSpace(character) || character == '{' || character == ';' || character == '\\' || character == '\'' || character == '"' {
						return l.fail(UnterminatedVariable, opening, start)
					}

					l.cursor++
				}

				if l.cursor == len(l.source) {
					return l.fail(UnterminatedVariable, opening, start)
				}

				l.cursor++
			}
		default:
			number = number && character >= '0' && character <= '9'
			l.cursor++
		}
	}

	kind := Ident

	if quoted {
		kind = String
	} else if number {
		kind = Number
	}

	return Token{Start: start, End: l.cursor, Kind: kind}
}

func (l *Lexer) fail(code ErrorCode, offset int, start int) Token {
	l.err = Error{Code: code, Offset: offset}

	return Token{Start: start, End: l.cursor, Kind: Illegal}
}

func isSpace(character byte) bool {
	return character == ' ' || character == '\t' || character == '\n' || character == '\r' || character == '\v' || character == '\f'
}
