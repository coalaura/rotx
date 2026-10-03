#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=versions.sh
source "$SCRIPT_DIR/versions.sh"

export LC_ALL=C
export LANG=C
export TZ=UTC
export SOURCE_DATE_EPOCH
export ZERO_AR_DATE=1

JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
CACHE_DIR="${TOR_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/rotx-tor}"
NATIVE_DIR="$ROOT_DIR/pkg/tor/native"
KEEP_WORK="${KEEP_WORK:-0}"
TOR_ENABLE_POW="${TOR_ENABLE_POW:-0}"

need() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'missing required build tool: %s\n' "$1" >&2
        exit 1
    }
}

check_tools() {
    local tool

    for tool in \
        awk \
        cmp \
        curl \
        find \
        grep \
        make \
        perl \
        pkg-config \
        sed \
        sha256sum \
        sort \
        tar \
        zig
    do
        need "$tool"
    done

    local actual_zig
    actual_zig="$(zig version)"

    if [[ "$actual_zig" != "$ZIG_VERSION" ]]; then
        printf 'wrong Zig version: have %s, require exactly %s\n' \
            "$actual_zig" "$ZIG_VERSION" >&2
        exit 1
    fi

    if [[ "$TOR_ENABLE_POW" != "0" && "$TOR_ENABLE_POW" != "1" ]]; then
        printf 'TOR_ENABLE_POW must be 0 or 1\n' >&2
        exit 1
    fi
}

download() {
    local url="$1"
    local output="$2"
    local sha256="$3"

    mkdir -p "$(dirname "$output")"

    if [[ ! -f "$output" ]]; then
        local temporary="${output}.tmp"
        rm -f "$temporary"

        curl \
            --fail \
            --location \
            --proto '=https' \
            --retry 5 \
            --retry-all-errors \
            --tlsv1.2 \
            --output "$temporary" \
            "$url"

        mv "$temporary" "$output"
    fi

    if ! printf '%s  %s\n' "$sha256" "$output" | sha256sum --check --status; then
        rm -f "$output"
        printf 'checksum mismatch: %s\n' "$output" >&2
        exit 1
    fi
}

download_sources() {
    download "$TOR_URL" \
        "$CACHE_DIR/tor-${TOR_VERSION}.tar.gz" \
        "$TOR_SHA256"

    download "$OPENSSL_URL" \
        "$CACHE_DIR/openssl-${OPENSSL_VERSION}.tar.gz" \
        "$OPENSSL_SHA256"

    download "$LIBEVENT_URL" \
        "$CACHE_DIR/libevent-${LIBEVENT_VERSION}.tar.gz" \
        "$LIBEVENT_SHA256"

    download "$ZLIB_URL" \
        "$CACHE_DIR/zlib-${ZLIB_VERSION}.tar.gz" \
        "$ZLIB_SHA256"
}

extract() {
    local archive="$1"
    local destination="$2"

    rm -rf "$destination"
    mkdir -p "$destination"
    tar -xf "$archive" --strip-components=1 -C "$destination"
}

write_cc_wrapper() {
    local path="$1"
    local target="$2"

    cat > "$path" <<WRAPPER
#!/usr/bin/env bash
exec zig cc -target "$target" "\$@"
WRAPPER
    chmod +x "$path"
}

write_cxx_wrapper() {
    local path="$1"
    local target="$2"

    cat > "$path" <<WRAPPER
#!/usr/bin/env bash
exec zig c++ -target "$target" "\$@"
WRAPPER
    chmod +x "$path"
}

write_ar_wrapper() {
    local path="$1"

    cat > "$path" <<'WRAPPER'
#!/usr/bin/env bash
exec zig ar "$@"
WRAPPER
    chmod +x "$path"
}

write_ranlib_wrapper() {
    local path="$1"

    cat > "$path" <<'WRAPPER'
#!/usr/bin/env bash
exec zig ranlib "$@"
WRAPPER
    chmod +x "$path"
}

write_build_cc_wrapper() {
    local path="$1"

    cat > "$path" <<'WRAPPER'
#!/usr/bin/env bash
exec zig cc "$@"
WRAPPER
    chmod +x "$path"
}

write_tor_cc_wrapper() {
    local path="$1"
    local target="$2"

    # Zig's optimized C modes implicitly define NDEBUG. C Tor deliberately
    # rejects NDEBUG because its assertions include security-critical checks.
    # Append -UNDEBUG after every build-system argument so Tor stays optimized
    # while preserving the assertion semantics required by upstream.
    cat > "$path" <<WRAPPER
#!/usr/bin/env bash
exec zig cc -target "$target" "\$@" -UNDEBUG
WRAPPER
    chmod +x "$path"
}

create_toolchain() {
    local tool_dir="$1"
    local host="$2"
    local zig_target="$3"

    mkdir -p "$tool_dir"

    write_cc_wrapper "$tool_dir/${host}-gcc" "$zig_target"
    write_cc_wrapper "$tool_dir/${host}-cc" "$zig_target"
    write_cc_wrapper "$tool_dir/${host}-clang" "$zig_target"
    write_cxx_wrapper "$tool_dir/${host}-g++" "$zig_target"
    write_cxx_wrapper "$tool_dir/${host}-c++" "$zig_target"
    write_ar_wrapper "$tool_dir/${host}-ar"
    write_ranlib_wrapper "$tool_dir/${host}-ranlib"
    write_build_cc_wrapper "$tool_dir/build-cc"
    write_tor_cc_wrapper "$tool_dir/tor-cc" "$zig_target"
}

build_zlib_linux() {
    local source_dir="$1"
    local prefix="$2"
    local host="$3"
    local compiler="$4"
    local archiver="$5"
    local ranlib="$6"
    local cflags="$7"

    (
        cd "$source_dir"

        CHOST="$host" \
        CC="$compiler" \
        AR="$archiver" \
        ARFLAGS="rcD" \
        RANLIB="$ranlib" \
        CFLAGS="$cflags" \
            ./configure \
                --static \
                --prefix="$prefix" \
                --libdir="$prefix/lib"

        make -j"$JOBS"
        make install
    )
}

build_zlib_windows() {
    local source_dir="$1"
    local prefix="$2"
    local compiler="$3"
    local archiver="$4"
    local cflags="$5"

    (
        cd "$source_dir"

        make \
            -f win32/Makefile.gcc \
            -j"$JOBS" \
            CC="$compiler" \
            AR="$archiver" \
            ARFLAGS="rcsD" \
            CFLAGS="$cflags" \
            libz.a
    )

    mkdir -p "$prefix/include" "$prefix/lib/pkgconfig"
    cp "$source_dir/zlib.h" "$source_dir/zconf.h" "$prefix/include/"
    cp "$source_dir/libz.a" "$prefix/lib/libz.a"

    cat > "$prefix/lib/pkgconfig/zlib.pc" <<PC
prefix=$prefix
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
sharedlibdir=\${libdir}
includedir=\${prefix}/include

Name: zlib
Description: zlib compression library
Version: $ZLIB_VERSION
Libs: -L\${libdir} -lz
Cflags: -I\${includedir}
PC
}

build_libevent() {
    local source_dir="$1"
    local prefix="$2"
    local host="$3"
    local compiler="$4"
    local archiver="$5"
    local ranlib="$6"
    local build_compiler="$7"
    local cflags="$8"

    (
        cd "$source_dir"

        CC="$compiler" \
        CC_FOR_BUILD="$build_compiler" \
        AR="$archiver" \
        ARFLAGS="crD" \
        RANLIB="$ranlib" \
        CFLAGS="$cflags" \
        CPPFLAGS="${CPPFLAGS:-}" \
            ./configure \
                --host="$host" \
                --prefix="$prefix" \
                --disable-shared \
                --enable-static \
                --disable-openssl \
                --disable-libevent-regress \
                --disable-samples

        make -j"$JOBS"
        make install
    )
}

build_openssl() {
    local source_dir="$1"
    local prefix="$2"
    local tool_prefix="$3"
    local openssl_target="$4"
    local cflags="$5"
    local no_asm="$6"

    cp "$SCRIPT_DIR/openssl-mingw-arm64.conf" \
        "$source_dir/Configurations/50-rotx-mingw-arm64.conf"

    local flags=(
        "$openssl_target"
        no-shared
        no-tests
        no-apps
        no-docs
        no-dso
        no-module
        no-zlib
        no-zstd
        no-makedepend
        "--cross-compile-prefix=$tool_prefix"
        "--prefix=$prefix"
        "--libdir=lib"
    )

    if [[ "$no_asm" == "yes" ]]; then
        flags+=(no-asm)
    fi

    local split_cflags=()
    read -r -a split_cflags <<< "$cflags"
    flags+=("${split_cflags[@]}")

    (
        cd "$source_dir"
        perl ./Configure "${flags[@]}"
        make -j"$JOBS"
        make install_sw
    )
}

build_tor() {
    local source_dir="$1"
    local build_dir="$2"
    local prefix="$3"
    local openssl_prefix="$4"
    local host="$5"
    local compiler="$6"
    local archiver="$7"
    local ranlib="$8"
    local build_compiler="$9"
    local cflags="${10}"

    mkdir -p "$build_dir"

    local pow_flags=(--disable-module-pow)
    if [[ "$TOR_ENABLE_POW" == "1" ]]; then
        # Tor's PoW module is only available in GPL-compatible builds.
        pow_flags=(--enable-gpl)
    fi

    (
        cd "$build_dir"

        PKG_CONFIG_PATH="$prefix/lib/pkgconfig:$openssl_prefix/lib/pkgconfig" \
        PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig:$openssl_prefix/lib/pkgconfig" \
        CC="$compiler" \
        CC_FOR_BUILD="$build_compiler" \
        AR="$archiver" \
        ARFLAGS="crD" \
        RANLIB="$ranlib" \
        CFLAGS="$cflags" \
        CPPFLAGS="-I$prefix/include -I$openssl_prefix/include" \
        LDFLAGS="-L$prefix/lib -L$openssl_prefix/lib" \
            "$source_dir/configure" \
                --host="$host" \
                --disable-module-relay \
                --disable-module-dirauth \
                "${pow_flags[@]}" \
                --disable-lzma \
                --disable-zstd \
                --disable-seccomp \
                --disable-unittests \
                --disable-asciidoc \
                --disable-manpage \
                --disable-html-manual \
                --disable-system-torrc \
                --disable-tool-name-check \
                --enable-static-openssl \
                --enable-static-libevent \
                --enable-static-zlib \
                --with-openssl-dir="$openssl_prefix" \
                --with-libevent-dir="$prefix" \
                --with-zlib-dir="$prefix"

        make -j"$JOBS" libtor.a
    )
}

combine_archives() {
    local working_dir="$1"
    local archiver="$2"
    local output="$3"
    shift 3

    local objects_dir="$working_dir/bundle"
    rm -rf "$objects_dir"
    mkdir -p "$objects_dir"

    local archive_index=0
    local object_index=0
    local archive
    local objects=()

    for archive in "$@"; do
        [[ -f "$archive" ]] || continue

        local archive_dir="$objects_dir/archive-$archive_index"
        mkdir -p "$archive_dir"

        (
            cd "$archive_dir"
            "$archiver" x "$archive"
        )

        while IFS= read -r -d '' object; do
            local suffix="${object##*.}"
            local unique="$objects_dir/object-$(printf '%06d' "$object_index").$suffix"

            mv "$object" "$unique"
            objects+=("$unique")
            object_index=$((object_index + 1))
        done < <(
            find "$archive_dir" -type f \( -name '*.o' -o -name '*.obj' \) -print0 \
                | sort -z
        )

        archive_index=$((archive_index + 1))
    done

    if [[ ${#objects[@]} -eq 0 ]]; then
        printf 'no object files found while combining archives\n' >&2
        exit 1
    fi

    mkdir -p "$(dirname "$output")"
    rm -f "$output"

    # LLVM ar (and therefore `zig ar`) supports deterministic mode with D.
    "$archiver" crsD "$output" "${objects[@]}"
}

link_probe() {
    local work_dir="$1"
    local compiler="$2"
    local bundle="$3"
    local platform="$4"
    local cflags="$5"

    local source="$work_dir/link-probe.c"
    local output="$work_dir/link-probe"

    cat > "$source" <<'C'
#ifdef _WIN32
#include <winsock2.h>
#endif
#include <feature/api/tor_api.h>

int main(int argc, char **argv) {
    tor_main_configuration_t *configuration = tor_main_configuration_new();
    if (configuration == 0) {
        return 1;
    }

    if (tor_main_configuration_set_command_line(configuration, argc, argv) != 0) {
        tor_main_configuration_free(configuration);
        return 1;
    }

    int result = tor_run_main(configuration);
    tor_main_configuration_free(configuration);

    return result;
}
C

    local compile_flags=(-O2 -I"$NATIVE_DIR/include")
    local split_cflags=()
    read -r -a split_cflags <<< "$cflags"
    compile_flags+=("${split_cflags[@]}")

    if [[ "$platform" == "windows" ]]; then
        "$compiler" \
            "${compile_flags[@]}" \
            "$source" \
            "$bundle" \
            -lws2_32 \
            -lcrypt32 \
            -lgdi32 \
            -liphlpapi \
            -lshlwapi \
            -luserenv \
            -lbcrypt \
            -lshell32 \
            -ladvapi32 \
            -luser32 \
            -o "$output.exe"
    else
        "$compiler" \
            "${compile_flags[@]}" \
            -static \
            "$source" \
            "$bundle" \
            -pthread \
            -lm \
            -ldl \
            -lrt \
            -o "$output"
    fi
}

write_manifest() {
    mkdir -p "$NATIVE_DIR"

    cat > "$NATIVE_DIR/VERSIONS" <<EOF_MANIFEST
zig=$ZIG_VERSION
tor=$TOR_VERSION
openssl=$OPENSSL_VERSION
libevent=$LIBEVENT_VERSION
zlib=$ZLIB_VERSION
pow=$TOR_ENABLE_POW
EOF_MANIFEST
}

build_target() {
    local requested="$1"

    local platform
    local architecture
    local output_name
    local zig_target
    local host
    local openssl_target
    local openssl_no_asm="no"
    local target_defines=""

    case "$requested" in
        linux/amd64)
            platform="linux"
            architecture="amd64"
            output_name="linux_amd64"
            zig_target="x86_64-linux-musl"
            host="x86_64-linux-musl"
            openssl_target="linux-x86_64"
            ;;
        linux/arm64)
            platform="linux"
            architecture="arm64"
            output_name="linux_arm64"
            zig_target="aarch64-linux-musl"
            host="aarch64-linux-musl"
            openssl_target="linux-aarch64"
            ;;
        windows/amd64)
            platform="windows"
            architecture="amd64"
            output_name="windows_amd64"
            zig_target="x86_64-windows-gnu"
            host="x86_64-w64-mingw32"
            openssl_target="mingw64"
            openssl_no_asm="yes"
            target_defines="-D_WIN32_WINNT=0x0601 -DWINVER=0x0601"
            ;;
        windows/arm64)
            platform="windows"
            architecture="arm64"
            output_name="windows_arm64"
            zig_target="aarch64-windows-gnu"
            host="aarch64-w64-mingw32"
            openssl_target="mingw-arm64"
            openssl_no_asm="yes"
            target_defines="-D_WIN32_WINNT=0x0A00 -DWINVER=0x0A00 -DNTDDI_VERSION=0x0A000000"
            ;;
        *)
            printf 'unsupported Tor target: %s\n' "$requested" >&2
            exit 2
            ;;
    esac

    local work_dir="${TOR_WORK_ROOT:-${TMPDIR:-/tmp}}/rotx-tor-${output_name}"
    local source_root="$work_dir/source"
    local tool_dir="$work_dir/toolchain"
    local prefix="$work_dir/prefix"
    local openssl_prefix="$work_dir/openssl"
    local tor_build="$work_dir/tor-build"

    rm -rf "$work_dir"
    mkdir -p "$source_root" "$prefix" "$openssl_prefix" "$tool_dir"

    create_toolchain "$tool_dir" "$host" "$zig_target"

    local tool_prefix="$tool_dir/${host}-"
    local compiler="${tool_prefix}gcc"
    local tor_compiler="$tool_dir/tor-cc"
    local archiver="${tool_prefix}ar"
    local ranlib="${tool_prefix}ranlib"
    local build_compiler="$tool_dir/build-cc"

    local normalized_source="/usr/src/rotx-tor"
    local cflags="-O2 -g0 -fno-ident -ffunction-sections -fdata-sections"
    cflags+=" -ffile-prefix-map=$work_dir=$normalized_source"
    cflags+=" -fdebug-prefix-map=$work_dir=$normalized_source"

    if [[ -n "$target_defines" ]]; then
        cflags+=" $target_defines"
    fi

    local zlib_source="$source_root/zlib"
    local libevent_source="$source_root/libevent"
    local openssl_source="$source_root/openssl"
    local tor_source="$source_root/tor"

    extract "$CACHE_DIR/zlib-${ZLIB_VERSION}.tar.gz" "$zlib_source"
    extract "$CACHE_DIR/libevent-${LIBEVENT_VERSION}.tar.gz" "$libevent_source"
    extract "$CACHE_DIR/openssl-${OPENSSL_VERSION}.tar.gz" "$openssl_source"
    extract "$CACHE_DIR/tor-${TOR_VERSION}.tar.gz" "$tor_source"

    printf '==> [%s] zlib %s\n' "$requested" "$ZLIB_VERSION"

    if [[ "$platform" == "windows" ]]; then
        build_zlib_windows \
            "$zlib_source" \
            "$prefix" \
            "$compiler" \
            "$archiver" \
            "$cflags"
    else
        build_zlib_linux \
            "$zlib_source" \
            "$prefix" \
            "$host" \
            "$compiler" \
            "$archiver" \
            "$ranlib" \
            "$cflags"
    fi

    printf '==> [%s] libevent %s\n' "$requested" "$LIBEVENT_VERSION"
    build_libevent \
        "$libevent_source" \
        "$prefix" \
        "$host" \
        "$compiler" \
        "$archiver" \
        "$ranlib" \
        "$build_compiler" \
        "$cflags"

    printf '==> [%s] OpenSSL %s\n' "$requested" "$OPENSSL_VERSION"
    build_openssl \
        "$openssl_source" \
        "$openssl_prefix" \
        "$tool_prefix" \
        "$openssl_target" \
        "$cflags" \
        "$openssl_no_asm"

    printf '==> [%s] Tor %s\n' "$requested" "$TOR_VERSION"
    build_tor \
        "$tor_source" \
        "$tor_build" \
        "$prefix" \
        "$openssl_prefix" \
        "$host" \
        "$tor_compiler" \
        "$archiver" \
        "$ranlib" \
        "$build_compiler" \
        "$cflags"

    [[ -f "$tor_build/libtor.a" ]] || {
        printf 'Tor did not produce libtor.a for %s\n' "$requested" >&2
        exit 1
    }

    [[ -f "$prefix/lib/libevent.a" ]] || {
        printf 'libevent did not produce libevent.a for %s\n' "$requested" >&2
        exit 1
    }

    [[ -f "$openssl_prefix/lib/libssl.a" ]] || {
        printf 'OpenSSL did not produce libssl.a for %s\n' "$requested" >&2
        exit 1
    }

    [[ -f "$openssl_prefix/lib/libcrypto.a" ]] || {
        printf 'OpenSSL did not produce libcrypto.a for %s\n' "$requested" >&2
        exit 1
    }

    [[ -f "$prefix/lib/libz.a" ]] || {
        printf 'zlib did not produce libz.a for %s\n' "$requested" >&2
        exit 1
    }

    mkdir -p "$NATIVE_DIR/include/feature/api"
    cp "$tor_source/src/feature/api/tor_api.h" \
        "$NATIVE_DIR/include/feature/api/tor_api.h"

    local archives=(
        "$tor_build/libtor.a"
        "$prefix/lib/libevent.a"
    )

    if [[ -f "$prefix/lib/libevent_pthreads.a" ]]; then
        archives+=("$prefix/lib/libevent_pthreads.a")
    fi

    archives+=(
        "$openssl_prefix/lib/libssl.a"
        "$openssl_prefix/lib/libcrypto.a"
        "$prefix/lib/libz.a"
    )

    local output_dir="$NATIVE_DIR/lib/$output_name"
    local bundle="$output_dir/librotx_tor.a"

    printf '==> [%s] combining static dependency closure\n' "$requested"
    combine_archives "$work_dir" "$archiver" "$bundle" "${archives[@]}"

    printf '==> [%s] verifying final native link\n' "$requested"
    link_probe "$work_dir" "$compiler" "$bundle" "$platform" "$cflags"

    write_manifest

    local digest
    digest="$(sha256sum "$bundle" | awk '{print $1}')"
    printf '==> [%s] %s\n' "$requested" "$bundle"
    printf '==> [%s] sha256 %s\n' "$requested" "$digest"

    if [[ "$KEEP_WORK" == "1" ]]; then
        printf '==> [%s] keeping build tree: %s\n' "$requested" "$work_dir"
    else
        rm -rf "$work_dir"
    fi
}
