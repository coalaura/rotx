package tor

import "sync/atomic"

type logHandler struct {
	write func(level, message string)
}

var activeLogHandler atomic.Pointer[logHandler]

func logLevel(severity int) string {
	// Tor uses syslog severity values on every supported platform.
	switch severity {
	case 3:
		return "err"
	case 4:
		return "warn"
	case 5:
		return "notice"
	case 6:
		return "info"
	case 7:
		return "debug"
	default:
		return "unknown"
	}
}
