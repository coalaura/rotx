package syntax

const (
	NoError ErrorCode = iota
	UnexpectedNUL
	UnterminatedQuote
	UnterminatedEscape
	UnterminatedVariable
	UnexpectedSemicolon
	UnexpectedBlockStart
	UnexpectedBlockEnd
	MissingTerminator
	UnclosedBlock
	ArgumentCapacity
)

type ErrorCode uint8

// Error is an allocation-free diagnostic. Offset is a zero-based byte offset;
// EOF errors point one byte past the input. Code == NoError means success.
type Error struct {
	Code   ErrorCode
	Offset int
}

func (err Error) Error() string {
	switch err.Code {
	case NoError:
		return ""
	case UnexpectedNUL:
		return "unexpected NUL byte"
	case UnterminatedQuote:
		return "unterminated quoted value"
	case UnterminatedEscape:
		return "unterminated escape sequence"
	case UnterminatedVariable:
		return "unterminated braced variable"
	case UnexpectedSemicolon:
		return "semicolon without a directive"
	case UnexpectedBlockStart:
		return "block without a name"
	case UnexpectedBlockEnd:
		return "unexpected closing brace"
	case MissingTerminator:
		return "expected semicolon or opening brace"
	case UnclosedBlock:
		return "unclosed block"
	case ArgumentCapacity:
		return "argument buffer capacity exceeded"
	}

	return "unknown config error"
}
