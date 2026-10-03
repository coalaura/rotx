package tor

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestControlAdmissionDeadline(t *testing.T) {
	controller := newControl(&nativeInstance{})

	controller.gate <- struct{}{}

	defer func() {
		<-controller.gate
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	finished := make(chan error, 1)

	go func() {
		_, err := controller.command(ctx, "GETINFO version")
		finished <- err
	}()

	select {
	case err := <-finished:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("command error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("command ignored its deadline while waiting for admission")
	}

	controller.cancel()
}

func TestCloseContextDeadlineAndEventualCleanup(t *testing.T) {
	native := &nativeInstance{}

	controller := newControl(native)

	instance := &Instance{
		native:    native,
		control:   controller,
		runDone:   make(chan struct{}),
		closeDone: make(chan struct{}),
	}

	close(instance.runDone)

	controller.gate <- struct{}{}

	t.Cleanup(func() {
		<-controller.gate

		select {
		case <-instance.closeDone:
		case <-time.After(time.Second):
			t.Error("cleanup did not finish after the command was released")
		}
	})

	// Both the initiating caller and a concurrent closer must honor their own deadlines.
	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)

		finished := make(chan error, 1)

		go func() {
			finished <- instance.CloseContext(ctx)
		}()

		select {
		case err := <-finished:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("close error = %v", err)
			}
		case <-time.After(time.Second):
			cancel()

			t.Fatal("CloseContext ignored its deadline")
		}

		cancel()
	}
}

func TestClosedControlRejectsCommands(t *testing.T) {
	controller := newControl(&nativeInstance{})

	controller.close()
	controller.close()

	_, err := controller.command(context.Background(), "GETINFO version")
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("command after close = %v", err)
	}
}

func TestCloseAfterControlAlreadyClosed(t *testing.T) {
	native := &nativeInstance{}

	controller := newControl(native)

	controller.close()

	instance := &Instance{
		native:    native,
		control:   controller,
		runDone:   make(chan struct{}),
		closeDone: make(chan struct{}),
	}

	close(instance.runDone)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := instance.CloseContext(ctx)
	if err != nil {
		t.Fatalf("closing an already closed owning controller: %v", err)
	}
}
