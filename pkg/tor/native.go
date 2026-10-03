//go:build (linux || windows) && cgo

package tor

/*
#cgo CFLAGS: -I${SRCDIR}/native/include

#cgo linux,amd64 LDFLAGS: ${SRCDIR}/native/lib/linux_amd64/librotx_tor.a -static -pthread -lm -ldl -lrt
#cgo linux,arm64 LDFLAGS: ${SRCDIR}/native/lib/linux_arm64/librotx_tor.a -static -pthread -lm -ldl -lrt

#cgo windows,amd64 CFLAGS: -D_WIN32_WINNT=0x0601 -DWINVER=0x0601
#cgo windows,arm64 CFLAGS: -D_WIN32_WINNT=0x0A00 -DWINVER=0x0A00 -DNTDDI_VERSION=0x0A000000
#cgo windows,amd64 LDFLAGS: ${SRCDIR}/native/lib/windows_amd64/librotx_tor.a -lws2_32 -lcrypt32 -lgdi32 -liphlpapi -lshlwapi -luserenv -lbcrypt -lshell32 -ladvapi32 -luser32
#cgo windows,arm64 LDFLAGS: ${SRCDIR}/native/lib/windows_arm64/librotx_tor.a -lws2_32 -lcrypt32 -lgdi32 -liphlpapi -lshlwapi -luserenv -lbcrypt -lshell32 -ladvapi32 -luser32

#include <stdlib.h>
#include "native.h"
*/
import "C"

import (
	"context"
	"fmt"
	"time"
	"unsafe"
)

const nativePollInterval = 100 * time.Millisecond

type nativeInstance struct {
	pointer *C.rotx_tor
}

func (i *nativeInstance) run() int {
	return int(C.rotx_tor_run(i.pointer))
}

func (i *nativeInstance) closeControl() {
	C.rotx_tor_control_close(i.pointer)
}

func (i *nativeInstance) free() {
	if i.pointer == nil {
		return
	}

	C.rotx_tor_free(i.pointer)

	i.pointer = nil
}

func (i *nativeInstance) read(ctx context.Context, buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}

	for {
		err := i.wait(ctx, false)
		if err != nil {
			return 0, err
		}

		result := int64(C.rotx_tor_control_read(
			i.pointer,
			unsafe.Pointer(&buffer[0]),
			C.size_t(len(buffer)),
		))

		switch {
		case result > 0:
			return int(result), nil
		case result == 0:
			return 0, fmt.Errorf("Tor control socket closed")
		case result == -2:
			continue
		default:
			return 0, nativeSocketError("read")
		}
	}
}

func (i *nativeInstance) write(ctx context.Context, buffer []byte) error {
	for len(buffer) > 0 {
		err := i.wait(ctx, true)
		if err != nil {
			return err
		}

		result := int64(C.rotx_tor_control_write(
			i.pointer,
			unsafe.Pointer(&buffer[0]),
			C.size_t(len(buffer)),
		))

		switch {
		case result > 0:
			buffer = buffer[result:]
		case result == -2:
			continue
		default:
			return nativeSocketError("write")
		}
	}

	return nil
}

func (i *nativeInstance) wait(ctx context.Context, writeReady bool) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		timeout := nativePollInterval

		deadline, hasDeadline := ctx.Deadline()
		if hasDeadline {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return ctx.Err()
			}

			if remaining < timeout {
				timeout = remaining
			}
		}

		timeoutMilliseconds := int(timeout / time.Millisecond)
		if timeoutMilliseconds < 1 {
			timeoutMilliseconds = 1
		}

		writeFlag := C.int(0)
		if writeReady {
			writeFlag = 1
		}

		result := int(C.rotx_tor_control_wait(
			i.pointer,
			writeFlag,
			C.int(timeoutMilliseconds),
		))

		switch result {
		case 1:
			return nil
		case 0:
			continue
		default:
			return nativeSocketError("wait")
		}
	}
}

func newNativeInstance(arguments []string) (*nativeInstance, error) {
	if len(arguments) == 0 {
		return nil, fmt.Errorf("Tor requires at least one argument")
	}

	pointerSize := C.size_t(unsafe.Sizeof(uintptr(0)))

	argumentMemory := C.calloc(C.size_t(len(arguments)), pointerSize)
	if argumentMemory == nil {
		return nil, fmt.Errorf("allocate Tor argument vector")
	}

	defer C.free(argumentMemory)

	argumentPointers := unsafe.Slice((**C.char)(argumentMemory), len(arguments))

	for index, argument := range arguments {
		argumentPointers[index] = C.CString(argument)
		if argumentPointers[index] == nil {
			for previous := range index {
				C.free(unsafe.Pointer(argumentPointers[previous]))
			}

			return nil, fmt.Errorf("allocate Tor argument")
		}
	}

	defer func() {
		for _, argument := range argumentPointers {
			C.free(unsafe.Pointer(argument))
		}
	}()

	pointer := C.rotx_tor_new(C.int(len(arguments)), (**C.char)(argumentMemory))
	if pointer == nil {
		return nil, fmt.Errorf("initialize embedded Tor")
	}

	return &nativeInstance{pointer: pointer}, nil
}

func nativeVersion() string {
	version := C.rotx_tor_version()
	if version == nil {
		return ""
	}

	return C.GoString(version)
}

func nativeSocketError(operation string) error {
	code := int(C.rotx_tor_control_error())

	return fmt.Errorf("Tor control socket %s failed with OS error %d", operation, code)
}
