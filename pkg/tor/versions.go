package tor

// LibraryVersions describes the linked native libraries.
type LibraryVersions struct {
	Tor      string
	OpenSSL  string
	Libevent string
	Zlib     string
	PoW      bool
}

// Versions queries the linked libraries without starting Tor. Unsupported builds return zero values.
func Versions() LibraryVersions {
	return nativeVersions()
}
