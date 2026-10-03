//go:build linux && cgo

package tor

import (
	"context"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNativeControlHighDescriptor(t *testing.T) {
	var limit unix.Rlimit

	err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit)
	if err != nil {
		t.Fatal(err)
	}

	if limit.Cur < 2048 {
		if limit.Max < 2048 {
			t.Skip("hard descriptor limit prevents testing descriptors above FD_SETSIZE")
		}

		increased := limit
		increased.Cur = 2048

		err = unix.Setrlimit(unix.RLIMIT_NOFILE, &increased)
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() {
			err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit)
			if err != nil {
				t.Error(err)
			}
		})
	}

	files := make([]*os.File, 0, 1025)

	t.Cleanup(func() {
		for _, file := range files {
			file.Close()
		}
	})

	for {
		file, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}

		files = append(files, file)

		if file.Fd() >= 1024 {
			break
		}
	}

	arguments := []string{"tor", "--DisableNetwork", "1"}

	native, err := newNativeInstance(arguments)
	if err != nil {
		t.Fatal(err)
	}

	defer native.free()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err = native.wait(ctx, true)
	if err != nil {
		t.Fatalf("wait on a control socket above FD_SETSIZE: %v", err)
	}
}
