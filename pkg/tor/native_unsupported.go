//go:build !cgo || (!linux && !windows)

package tor

import (
	"context"
	"fmt"
)

type nativeInstance struct{}

func (i *nativeInstance) run(func(level, message string)) int {
	return -1
}

func (i *nativeInstance) closeControl() {}

func (i *nativeInstance) free() {}

func (i *nativeInstance) read(context.Context, []byte) (int, error) {
	return 0, fmt.Errorf("embedded Tor requires cgo on Linux or Windows")
}

func (i *nativeInstance) write(context.Context, []byte) error {
	return fmt.Errorf("embedded Tor requires cgo on Linux or Windows")
}

func nativeVersion() string {
	return ""
}

func newNativeInstance([]string) (*nativeInstance, error) {
	return nil, fmt.Errorf("embedded Tor requires cgo on Linux or Windows")
}
