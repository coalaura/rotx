//go:build (linux || windows) && cgo

package tor

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type pendingDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (ctx pendingDeadlineContext) Deadline() (time.Time, bool) {
	return ctx.deadline, true
}

func TestNativeWaitExpiredDeadline(t *testing.T) {
	// Reproduce the interval between the deadline passing and its timer cancelling the context.
	ctx := pendingDeadlineContext{
		Context:  context.Background(),
		deadline: time.Now().Add(-time.Second),
	}

	native := &nativeInstance{}

	err := native.wait(ctx, false)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline with pending timer returned %v", err)
	}
}

func TestControlCloseInterruptsPendingReply(t *testing.T) {
	arguments := []string{"tor", "--DisableNetwork", "1"}

	native, err := newNativeInstance(arguments)
	if err != nil {
		t.Fatal(err)
	}

	controller := newControl(native)

	t.Cleanup(func() {
		controller.close()
		native.free()
	})

	finished := make(chan error, 1)

	go func() {
		// No Tor main loop is running: the command cannot receive a reply.
		_, commandError := controller.command(context.Background(), "GETINFO version")
		finished <- commandError
	}()

	deadline := time.After(time.Second)

	for len(controller.gate) == 0 {
		select {
		case <-deadline:
			t.Fatal("command did not acquire the control connection")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	closed := make(chan struct{})

	go func() {
		controller.close()
		close(closed)
	}()

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("closing control did not interrupt pending I/O")
	}

	err = <-finished
	if err == nil {
		t.Fatal("interrupted command succeeded")
	}

	_, err = controller.command(context.Background(), "GETINFO version")
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed control was reused: %v", err)
	}
}

func TestCancelledExchangeClosesControl(t *testing.T) {
	arguments := []string{"tor", "--DisableNetwork", "1"}

	native, err := newNativeInstance(arguments)
	if err != nil {
		t.Fatal(err)
	}

	controller := newControl(native)

	t.Cleanup(func() {
		controller.close()
		native.free()
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = controller.command(ctx, "GETINFO version")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pending command error = %v", err)
	}

	retryContext, cancelRetry := context.WithTimeout(context.Background(), time.Second)
	defer cancelRetry()

	_, err = controller.command(retryContext, "GETINFO version")
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("cancelled exchange left a reusable control stream: %v", err)
	}
}
