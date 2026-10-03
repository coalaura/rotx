package tor

import "testing"

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
