#ifndef ROTX_TOR_NATIVE_H
#define ROTX_TOR_NATIVE_H

#include <stddef.h>
#include <stdint.h>

typedef struct rotx_tor rotx_tor;

rotx_tor *rotx_tor_new(int argc, const char *const *argv);
int rotx_tor_run(rotx_tor *instance);
void rotx_tor_capture_logs(int enabled);
void rotx_tor_free(rotx_tor *instance);

const char *rotx_tor_version(void);
int rotx_tor_has_pow(void);
const char *rotx_openssl_version(void);
const char *rotx_libevent_version(void);
const char *rotx_zlib_version(void);

int rotx_tor_control_wait(rotx_tor *instance, int write_ready, int timeout_ms);
int64_t rotx_tor_control_read(rotx_tor *instance, void *buffer, size_t size);
int64_t rotx_tor_control_write(rotx_tor *instance, const void *buffer, size_t size);
int rotx_tor_control_error(void);
void rotx_tor_control_close(rotx_tor *instance);

#endif
