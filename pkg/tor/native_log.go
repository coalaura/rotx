//go:build (linux || windows) && cgo

package tor

import "C"

import "strings"

//export rotxTorLog
func rotxTorLog(severity C.int, message *C.char) {
	handler := activeLogHandler.Load()
	if handler == nil {
		return
	}

	// Copy before returning to Tor, which owns and reuses the message buffer.
	text := C.GoString(message)

	text = strings.TrimSuffix(text, "\n")
	text = strings.TrimSuffix(text, "\r")

	handler.write(logLevel(int(severity)), text)
}
