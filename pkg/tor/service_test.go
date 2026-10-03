package tor

import (
	"strings"
	"testing"
)

const testServiceID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestValidateService(t *testing.T) {
	service := Service{
		ID:         testServiceID,
		Target:     "127.0.0.1:1978",
		PrivateKey: make([]byte, expandedEd25519PrivateKeySize),
		Port:       80,
	}

	err := validateService(service)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateServiceRejectsNonLoopbackTarget(t *testing.T) {
	service := Service{
		ID:         testServiceID,
		Target:     "192.0.2.1:1978",
		PrivateKey: make([]byte, expandedEd25519PrivateKeySize),
		Port:       80,
	}

	err := validateService(service)
	if err == nil {
		t.Fatal("non-loopback target accepted")
	}
}

func TestOnionAuthorizationCommand(t *testing.T) {
	service := Service{
		ID:         testServiceID,
		Target:     "127.0.0.1:1978",
		PrivateKey: make([]byte, expandedEd25519PrivateKeySize),
		ClientKeys: []string{strings.Repeat("A", 52), strings.Repeat("B", 52)},
		Port:       80,
		PoW:        true,
	}

	command := string(appendOnionCommand(nil, service))
	expected := " Port=80,127.0.0.1:1978 PoWDefensesEnabled=1 Flags=V3Auth ClientAuthV3=" + service.ClientKeys[0] + " ClientAuthV3=" + service.ClientKeys[1]

	if !strings.HasSuffix(command, expected) || !strings.HasPrefix(command, "ADD_ONION ED25519-V3:") {
		t.Fatalf("unexpected authenticated service command: %s", command)
	}

	service.ClientKeys = nil
	service.PoW = false

	command = string(appendOnionCommand(nil, service))
	if !strings.HasSuffix(command, " PoWDefensesEnabled=0") || strings.Contains(command, "V3Auth") {
		t.Fatal("public service must explicitly disable PoW without client authorization")
	}

	service.ClientKeys = []string{"invalid\r\nQUIT"}

	err := validateService(service)
	if err == nil {
		t.Fatal("invalid client key accepted")
	}
}
