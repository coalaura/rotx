package syntax

import (
	"path/filepath"
	"testing"
)

func TestParseIndependentSyntax(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "arbitrary.conf")

	source := []byte(`outer { unknown "quoted value"; first { second { third { fourth; } } } }`)

	statements, err := Parse(source, filename)
	if err != nil {
		t.Fatal(err)
	}

	clear(source)

	if len(statements) != 1 || statements[0].Name != "outer" || !statements[0].Block {
		t.Fatalf("unexpected syntax tree: %#v", statements)
	}

	directive := &statements[0].Children[0]
	if directive.Name != "unknown" || directive.Args[0].Value != "quoted value" || !directive.Args[0].Quoted || directive.Position.File != filename || directive.Position.Column != 9 {
		t.Fatalf("syntax lost argument ownership or position: %#v", directive)
	}
}
