package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/coalaura/plain"
	"github.com/coalaura/rotx/pkg/tor"
)

func TestDescriptorPublicationLogging(t *testing.T) {
	var output bytes.Buffer

	logger := plain.New(plain.WithTarget(&output), plain.WithDate("timestamp"))

	handler := newDescriptorLogger(logger, 2)

	serviceID := strings.Repeat("a", 56)
	actions := []string{"CREATED", "UPLOAD", "UPLOADED"}

	for _, action := range actions {
		event := tor.DescriptorEvent{Action: action, ServiceID: serviceID, Directory: "$directory"}

		handler(event)
		handler(event)
	}

	want := "timestamp Descriptor created: " + serviceID + ".onion\n"
	want += "timestamp Descriptor uploading: " + serviceID + ".onion\n"
	want += "timestamp Descriptor published: " + serviceID + ".onion\n"

	if output.String() != want {
		t.Fatalf("publication log = %q, want %q", output.String(), want)
	}

	handler(tor.DescriptorEvent{Action: "FAILED", ServiceID: serviceID, Directory: "$failed", Reason: "UPLOAD_REJECTED"})

	if !strings.Contains(output.String(), "UPLOAD_REJECTED (HSDir $failed)") {
		t.Fatalf("publication failure was lost after first success: %q", output.String())
	}

	second := strings.Repeat("b", 56)

	handler(tor.DescriptorEvent{Action: "UPLOADED", ServiceID: second, Directory: "$directory"})

	if !strings.Contains(output.String(), "Descriptor published: "+second+".onion") {
		t.Fatal("second onion's publication was suppressed")
	}
}
