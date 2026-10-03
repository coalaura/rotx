package tor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDescriptorEventsBetweenReplyLines(t *testing.T) {
	serviceID := strings.Repeat("a", 56)
	wire := "250-version=0.4.9.13\r\n650 HS_DESC UPLOADED " + serviceID + " UNKNOWN $directory\r\n250 OK\r\n"

	controller := newControl(&nativeInstance{})

	controller.buffer = []byte(wire)

	defer controller.cancel()

	var events []DescriptorEvent

	controller.event = descriptorHandler(func(event DescriptorEvent) {
		events = append(events, event)
	})

	reply, err := controller.readReply(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	version, ok := reply.Value("version")
	if !ok || version != "0.4.9.13" || len(reply.Lines) != 2 || reply.Code != 250 {
		t.Fatalf("interleaved event corrupted reply: %+v", reply)
	}

	if len(events) != 1 || events[0].Action != "UPLOADED" || events[0].ServiceID != serviceID || events[0].Directory != "$directory" {
		t.Fatalf("descriptor events = %+v", events)
	}
}

func TestControlReadsEventsWhileIdle(t *testing.T) {
	serviceID := strings.Repeat("a", 56)
	wire := "650 HS_DESC FAILED " + serviceID + " UNKNOWN $directory REASON=UPLOAD_REJECTED\r\n"

	controller := newControl(&nativeInstance{})

	controller.buffer = []byte(wire)

	events := make(chan DescriptorEvent, 1)

	controller.event = descriptorHandler(func(event DescriptorEvent) {
		events <- event

		controller.cancel()
	})

	go controller.readLoop()

	defer func() {
		controller.cancel()

		select {
		case <-controller.readDone:
		case <-time.After(time.Second):
			t.Error("idle event reader did not stop")
		}
	}()

	select {
	case event := <-events:
		if event.Action != "FAILED" || event.Reason != "UPLOAD_REJECTED" {
			t.Fatalf("failure event = %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("descriptor event was not delivered without a control command")
	}
}

func TestCancelledControlReaderDoesNotBlockOnReply(t *testing.T) {
	controller := newControl(&nativeInstance{})

	controller.buffer = []byte("250 OK\r\n")
	controller.reading = true

	go controller.readLoop()

	finished := make(chan struct{})

	go func() {
		controller.close()
		close(finished)
	}()

	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("closing reader blocked while an unclaimed reply was pending")
	}

	if !errors.Is(controller.lifetime.Err(), context.Canceled) {
		t.Fatal("control lifetime was not canceled")
	}
}

func TestDescriptorEventFiltering(t *testing.T) {
	serviceID := strings.Repeat("a", 56)

	lines := []string{
		"HS_DESC UPLOADED UNKNOWN UNKNOWN $directory",
		"HS_DESC UPLOADED " + serviceID,
		"HS_DESC RECEIVED " + serviceID + " NO_AUTH $directory",
		"STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100",
		"HS_DESC UPLOADED " + strings.Repeat("A", 56) + " UNKNOWN $directory",
	}

	for _, line := range lines {
		_, ok := parseDescriptorEvent(line)
		if ok {
			t.Fatalf("accepted unrelated or malformed event %q", line)
		}
	}
}
