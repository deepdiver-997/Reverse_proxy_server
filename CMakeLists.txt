cmake_minimum_required(VERSION 3.20)
project(ebpf-quic-proxy VERSION 0.1.0 LANGUAGES CXX)

# Core (src/, tests/) is C++17.  Only the lsquic H3 repro harness uses C++20
# designated initializers (lsquic_h3_server_min.cpp), bumped per-target below.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Dependencies ──────────────────────────────────────────

# asio is header-only; brew puts it in /opt/homebrew/include (already on path)
find_package(spdlog REQUIRED)
find_package(toml11 REQUIRED)

# lsquic + BoringSSL — pre-built in third_party/
set(LSQUIC_ROOT ${CMAKE_SOURCE_DIR}/third_party/lsquic)
set(BORINGSSL_ROOT ${CMAKE_SOURCE_DIR}/third_party/boringssl)

add_library(lsquic STATIC IMPORTED)
set_target_properties(lsquic PROPERTIES
    IMPORTED_LOCATION ${LSQUIC_ROOT}/build/src/liblsquic/liblsquic.a
    INTERFACE_INCLUDE_DIRECTORIES "${LSQUIC_ROOT}/include;${BORINGSSL_ROOT}/include"
)
target_link_libraries(lsquic INTERFACE
    ${BORINGSSL_ROOT}/build/libssl.a
    ${BORINGSSL_ROOT}/build/libcrypto.a
    -lz
)

# Catch2 (brew install catch2)
find_package(Catch2 REQUIRED)

# ── Main executable ───────────────────────────────────────

add_executable(ebpf-quic-proxy
    src/main.cpp
    src/config.cpp
    src/transport/tcp_transport.cpp
    src/transport/quic_transport.cpp
    src/transport/quic_demux.cpp
    src/codec/http_message.cpp
    src/codec/h1_codec.cpp
    src/codec/h3_codec.cpp
    src/proxy/router.cpp
    src/proxy/upstream_pool.cpp
    src/proxy/proxy_core.cpp
    src/proxy/relay_session.cpp
)

target_include_directories(ebpf-quic-proxy PRIVATE
    src
    ${BORINGSSL_ROOT}/include   # MUST come before system paths
)
target_link_libraries(ebpf-quic-proxy PRIVATE
    spdlog::spdlog
    toml11::toml11
    lsquic
)

# ── Examples ──────────────────────────────────────────────

# Minimal prototype of the CID-based demux (level-1 routing DCID -> engine).
add_executable(quic_demux_demo
    examples/quic_demux_demo.cpp
)
target_include_directories(quic_demux_demo PRIVATE ${BORINGSSL_ROOT}/include)
target_link_libraries(quic_demux_demo PRIVATE lsquic)

# Minimal standalone lsquic HTTP/3 server — repro harness for the upstream
# handshake bug (server Initial SCID != registered SCID under 20-byte client
# DCID).  Depends only on lsquic+BoringSSL, not the proxy layers.  See
# examples/lsquic_h3_server_min.cpp header comment.
add_executable(lsquic_h3_min
    examples/lsquic_h3_server_min.cpp
)
target_include_directories(lsquic_h3_min PRIVATE ${BORINGSSL_ROOT}/include)
target_link_libraries(lsquic_h3_min PRIVATE lsquic)
set_property(TARGET lsquic_h3_min PROPERTY CXX_STANDARD 20)  # designated initializers

# ── lsquic A+B interop patch guard ────────────────────────
# third_party/ is gitignored, so a fresh submodule checkout silently loses the
# vendored H3-interop patch and the H3 path breaks again.  This custom target
# re-applies it to the vendored source and fails loudly if the prebuilt
# liblsquic.a is stale (built from unpatched source).  It runs before every
# target that links lsquic — deliberately NOT ALL, so test-only builds
# (proxy_tests doesn't link lsquic) stay unblocked.
add_custom_target(lsquic-patch-guard
    COMMAND bash ${CMAKE_SOURCE_DIR}/scripts/ensure_lsquic_patch.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Checking lsquic interop patch on the vendored build"
    VERBATIM
)
add_dependencies(ebpf-quic-proxy lsquic-patch-guard)
add_dependencies(quic_demux_demo lsquic-patch-guard)
add_dependencies(lsquic_h3_min lsquic-patch-guard)

# ── Tests ─────────────────────────────────────────────────

add_executable(proxy_tests
    tests/test_h1_codec.cpp
    tests/test_h3_codec.cpp
    tests/test_config.cpp
    src/codec/h1_codec.cpp
    src/codec/h3_codec.cpp
    src/codec/http_message.cpp
    src/config.cpp
)
target_include_directories(proxy_tests PRIVATE src /opt/homebrew/include)
target_link_libraries(proxy_tests PRIVATE
    Catch2::Catch2WithMain
    spdlog::spdlog
)
