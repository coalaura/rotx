package config

const (
	Directive EventKind = iota + 1
	BlockStart
	BlockEnd
)

type EventKind uint8

// Event describes a directive or a block boundary. Depth is zero at the root;
// a block's start and end have the same depth. Name and Args are empty at BlockEnd.
// Args borrows the caller's buffer and is valid until that buffer is reused.
// Start and End delimit the entire statement, including its semicolon or brace.
type Event struct {
	Args  []Token
	Name  Token
	Start int
	End   int
	Depth int
	Kind  EventKind
}

// Parser validates nesting while emitting events without building a tree or
// allocating a block stack. There is no nesting limit imposed by the parser.
type Parser struct {
	lexer    Lexer
	err      Error
	depth    int
	finished bool
}

// Reset reuses the parser. The input must remain unchanged while parsing.
func (p *Parser) Reset(source []byte) {
	p.lexer.Reset(source)
	p.err = Error{}
	p.depth = 0
	p.finished = false
}

func (p *Parser) Err() Error {
	return p.err
}

// Next returns false at EOF or on an error; inspect Err to distinguish them.
// Arguments' capacity must fit the argument list, excluding the name. If it is
// too small, parsing stops with ArgumentCapacity instead of allocating.
func (p *Parser) Next(arguments []Token) (Event, bool) {
	if p.finished {
		return Event{}, false
	}

	name := p.nextToken()

	switch name.Kind {
	case EOF:
		if p.depth != 0 {
			return p.fail(UnclosedBlock, name.Start)
		}

		p.finished = true

		return Event{}, false
	case Illegal:
		return p.failLexer()
	case Semicolon:
		return p.fail(UnexpectedSemicolon, name.Start)
	case LBrace:
		return p.fail(UnexpectedBlockStart, name.Start)
	case RBrace:
		if p.depth == 0 {
			return p.fail(UnexpectedBlockEnd, name.Start)
		}

		p.depth--

		return Event{Start: name.Start, End: name.End, Depth: p.depth, Kind: BlockEnd}, true
	}

	arguments = arguments[:cap(arguments)]
	argumentCount := 0

	for {
		token := p.nextToken()

		switch token.Kind {
		case Illegal:
			return p.failLexer()
		case EOF, RBrace:
			return p.fail(MissingTerminator, token.Start)
		case Semicolon, LBrace:
			event := Event{
				Name:  name,
				Args:  arguments[:argumentCount],
				Start: name.Start,
				End:   token.End,
				Depth: p.depth,
				Kind:  Directive,
			}

			if token.Kind == LBrace {
				event.Kind = BlockStart

				p.depth++
			}

			return event, true
		default:
			if argumentCount == len(arguments) {
				return p.fail(ArgumentCapacity, token.Start)
			}

			arguments[argumentCount] = token

			argumentCount++
		}
	}
}

func (p *Parser) nextToken() Token {
	for {
		token := p.lexer.Next()
		if token.Kind != Comment {
			return token
		}
	}
}

func (p *Parser) fail(code ErrorCode, offset int) (Event, bool) {
	p.err = Error{Code: code, Offset: offset}
	p.finished = true

	return Event{}, false
}

func (p *Parser) failLexer() (Event, bool) {
	p.err = p.lexer.Err()
	p.finished = true

	return Event{}, false
}
