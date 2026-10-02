//go:build linux || windows

#include "native.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <feature/api/tor_api.h>

struct rotx_tor {
	tor_main_configuration_t *configuration;
	tor_control_socket_t control;
	char **arguments;
	int argument_count;
#ifdef _WIN32
	int winsock_started;
#endif
};

static char *rotx_strdup(const char *value) {
	size_t length = strlen(value) + 1;
	char *copy = malloc(length);

	if (copy == NULL) {
		return NULL;
	}

	memcpy(copy, value, length);

	return copy;
}

static void rotx_free_arguments(char **arguments, int count) {
	if (arguments == NULL) {
		return;
	}

	for (int index = 0; index < count; index++) {
		free(arguments[index]);
	}

	free(arguments);
}

static int rotx_socket_would_block(void) {
#ifdef _WIN32
	int error = WSAGetLastError();
	return error == WSAEWOULDBLOCK || error == WSAEINTR;
#else
	return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
}

static int rotx_socket_wait(tor_control_socket_t socket_value, int write_ready, int timeout_ms) {
	for (;;) {
		fd_set descriptors;
		struct timeval timeout;

		FD_ZERO(&descriptors);
		FD_SET(socket_value, &descriptors);

		timeout.tv_sec = timeout_ms / 1000;
		timeout.tv_usec = (timeout_ms % 1000) * 1000;

		int result;

#ifdef _WIN32
		if (write_ready) {
			result = select(0, NULL, &descriptors, NULL, &timeout);
		} else {
			result = select(0, &descriptors, NULL, NULL, &timeout);
		}
#else
		if (write_ready) {
			result = select(socket_value + 1, NULL, &descriptors, NULL, &timeout);
		} else {
			result = select(socket_value + 1, &descriptors, NULL, NULL, &timeout);
		}
#endif

		if (result >= 0) {
			return result;
		}

#ifdef _WIN32
		if (WSAGetLastError() != WSAEINTR) {
			return -1;
		}
#else
		if (errno != EINTR) {
			return -1;
		}
#endif
	}
}

rotx_tor *rotx_tor_new(int argc, const char *const *argv) {
	if (argc <= 0 || argv == NULL) {
		return NULL;
	}

	rotx_tor *instance = calloc(1, sizeof(*instance));
	if (instance == NULL) {
		return NULL;
	}

	instance->control = INVALID_TOR_CONTROL_SOCKET;
	instance->argument_count = argc;

#ifdef _WIN32
	WSADATA winsock_data;
	if (WSAStartup(MAKEWORD(2, 2), &winsock_data) != 0) {
		free(instance);
		return NULL;
	}
	instance->winsock_started = 1;
#endif
	instance->arguments = calloc((size_t)argc, sizeof(*instance->arguments));

	if (instance->arguments == NULL) {
#ifdef _WIN32
		WSACleanup();
#endif
		free(instance);
		return NULL;
	}

	for (int index = 0; index < argc; index++) {
		instance->arguments[index] = rotx_strdup(argv[index]);
		if (instance->arguments[index] == NULL) {
			rotx_free_arguments(instance->arguments, argc);
#ifdef _WIN32
			WSACleanup();
#endif
			free(instance);
			return NULL;
		}
	}

	instance->configuration = tor_main_configuration_new();
	if (instance->configuration == NULL) {
		rotx_free_arguments(instance->arguments, argc);
#ifdef _WIN32
		WSACleanup();
#endif
		free(instance);
		return NULL;
	}

	int result = tor_main_configuration_set_command_line(
		instance->configuration,
		argc,
		instance->arguments
	);

	if (result != 0) {
		tor_main_configuration_free(instance->configuration);
		rotx_free_arguments(instance->arguments, argc);
#ifdef _WIN32
		WSACleanup();
#endif
		free(instance);
		return NULL;
	}

	instance->control = tor_main_configuration_setup_control_socket(instance->configuration);
	if (instance->control == INVALID_TOR_CONTROL_SOCKET) {
		tor_main_configuration_free(instance->configuration);
		rotx_free_arguments(instance->arguments, argc);
#ifdef _WIN32
		WSACleanup();
#endif
		free(instance);
		return NULL;
	}

	return instance;
}

int rotx_tor_run(rotx_tor *instance) {
	if (instance == NULL || instance->configuration == NULL) {
		return -1;
	}

	return tor_run_main(instance->configuration);
}

void rotx_tor_free(rotx_tor *instance) {
	if (instance == NULL) {
		return;
	}

	rotx_tor_control_close(instance);

	if (instance->configuration != NULL) {
		tor_main_configuration_free(instance->configuration);
	}

	rotx_free_arguments(instance->arguments, instance->argument_count);
#ifdef _WIN32
	if (instance->winsock_started) {
		WSACleanup();
	}
#endif
	free(instance);
}

const char *rotx_tor_version(void) {
	return tor_api_get_provider_version();
}

int rotx_tor_control_wait(rotx_tor *instance, int write_ready, int timeout_ms) {
	if (instance == NULL || instance->control == INVALID_TOR_CONTROL_SOCKET) {
		return -1;
	}

	if (timeout_ms < 0) {
		timeout_ms = 0;
	}

	return rotx_socket_wait(instance->control, write_ready, timeout_ms);
}

int64_t rotx_tor_control_read(rotx_tor *instance, void *buffer, size_t size) {
	if (instance == NULL || instance->control == INVALID_TOR_CONTROL_SOCKET || buffer == NULL) {
		return -1;
	}

	if (size > INT_MAX) {
		size = INT_MAX;
	}

#ifdef _WIN32
	int result = recv(instance->control, buffer, (int)size, 0);
#else
	ssize_t result = recv(instance->control, buffer, size, 0);
#endif

	if (result >= 0) {
		return (int64_t)result;
	}

	if (rotx_socket_would_block()) {
		return -2;
	}

	return -1;
}

int64_t rotx_tor_control_write(rotx_tor *instance, const void *buffer, size_t size) {
	if (instance == NULL || instance->control == INVALID_TOR_CONTROL_SOCKET || buffer == NULL) {
		return -1;
	}

	if (size > INT_MAX) {
		size = INT_MAX;
	}

#ifdef _WIN32
	int result = send(instance->control, buffer, (int)size, 0);
#else
#ifdef MSG_NOSIGNAL
	ssize_t result = send(instance->control, buffer, size, MSG_NOSIGNAL);
#else
	ssize_t result = send(instance->control, buffer, size, 0);
#endif
#endif

	if (result >= 0) {
		return (int64_t)result;
	}

	if (rotx_socket_would_block()) {
		return -2;
	}

	return -1;
}

int rotx_tor_control_error(void) {
#ifdef _WIN32
	return WSAGetLastError();
#else
	return errno;
#endif
}

void rotx_tor_control_close(rotx_tor *instance) {
	if (instance == NULL || instance->control == INVALID_TOR_CONTROL_SOCKET) {
		return;
	}

#ifdef _WIN32
	shutdown(instance->control, SD_BOTH);
	closesocket(instance->control);
#else
	shutdown(instance->control, SHUT_RDWR);
	close(instance->control);
#endif

	instance->control = INVALID_TOR_CONTROL_SOCKET;
}
