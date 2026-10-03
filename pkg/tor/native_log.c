//go:build linux || windows

#include "native.h"

#include <stdint.h>

extern void rotxTorLog(int severity, char *message);
extern void rotx_tor_set_log_callback(void (*callback)(int, uint64_t, const char *));

static void rotx_log_message(int severity, uint64_t domain, const char *message) {
	(void)domain;
	rotxTorLog(severity, (char *)message);
}

void rotx_tor_capture_logs(int enabled) {
	rotx_tor_set_log_callback(enabled ? rotx_log_message : NULL);
}
