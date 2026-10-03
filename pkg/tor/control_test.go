package tor

import "testing"

type controlLineTest struct {
	line      string
	text      string
	code      int
	separator byte
}

func TestParseControlLine(t *testing.T) {
	tests := []controlLineTest{
		{line: "250 OK", text: "OK", code: 250, separator: ' '},
		{line: "250-ServiceID=example", text: "ServiceID=example", code: 250, separator: '-'},
		{line: "250+config-text=", text: "config-text=", code: 250, separator: '+'},
		{line: "650 STATUS_CLIENT NOTICE BOOTSTRAP", text: "STATUS_CLIENT NOTICE BOOTSTRAP", code: 650, separator: ' '},
	}

	for _, test := range tests {
		code, separator, text, err := parseControlLine(test.line)
		if err != nil {
			t.Fatalf("parse %q: %v", test.line, err)
		}

		if code != test.code || separator != test.separator || text != test.text {
			t.Fatalf(
				"parse %q = (%d, %q, %q), want (%d, %q, %q)",
				test.line,
				code,
				separator,
				text,
				test.code,
				test.separator,
				test.text,
			)
		}
	}
}

func TestParseControlLineRejectsMalformed(t *testing.T) {
	lines := []string{
		"",
		"250",
		"abc OK",
		"250_OK",
		"999 OK",
	}

	for _, line := range lines {
		_, _, _, err := parseControlLine(line)
		if err == nil {
			t.Fatalf("parse %q succeeded", line)
		}
	}
}

func TestReplyValue(t *testing.T) {
	reply := Reply{
		Code: 250,
		Lines: []string{
			"ServiceID=garfieldexample",
			"OK",
		},
	}

	value, ok := reply.Value("ServiceID")
	if !ok {
		t.Fatal("ServiceID not found")
	}

	if value != "garfieldexample" {
		t.Fatalf("ServiceID = %q", value)
	}
}
