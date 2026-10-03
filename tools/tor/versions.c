#include "../../pkg/tor/native.h"

#include <event2/event.h>
#include <openssl/crypto.h>
#include <zlib.h>

const char *rotx_openssl_version(void) {
	return OpenSSL_version(OPENSSL_VERSION_STRING);
}

const char *rotx_libevent_version(void) {
	return event_get_version();
}

const char *rotx_zlib_version(void) {
	return zlibVersion();
}
