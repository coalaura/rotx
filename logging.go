package main

import "github.com/coalaura/plain"

func writeTorLog(logger *plain.Plain, level, message string) {
	color := logger.Theme(plain.Dimmed)

	switch level {
	case "info":
		color = logger.Theme(plain.Highlight)
	case "notice":
		color = logger.Theme(plain.Success)
	case "warn":
		color = logger.Theme(plain.Warn)
	case "err":
		color = logger.Theme(plain.Error)
	}

	line := "[tor/" + color + level + logger.Theme(plain.Reset) + "] " + message

	logger.Writeln("", line, false, false)
}
