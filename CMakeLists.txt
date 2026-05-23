cmake_minimum_required(VERSION 3.20)
project(ebpf-quic-proxy VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Dependencies (all from brew, no FetchContent) ─────────

# asio is header-only; brew puts it in /opt/homebrew/include (already on path)
find_package(spdlog REQUIRED)
find_package(toml11 REQUIRED)

# Catch2 — brew doesn't have it, one-time FetchContent
include(FetchContent)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.7.1
)
FetchContent_MakeAvailable(Catch2)

# ── Main executable ───────────────────────────────────────

add_executable(ebpf-quic-proxy
    src/main.cpp
    src/config.cpp
    src/transport/tcp_transport.cpp
    src/codec/http_message.cpp
    src/codec/h1_codec.cpp
    src/proxy/router.cpp
    src/proxy/upstream_pool.cpp
    src/proxy/proxy_core.cpp
)

target_include_directories(ebpf-quic-proxy PRIVATE src)
target_link_libraries(ebpf-quic-proxy PRIVATE
    spdlog::spdlog
    toml11::toml11
)

# ── Tests ─────────────────────────────────────────────────

add_executable(proxy_tests
    tests/test_h1_codec.cpp
    src/codec/h1_codec.cpp
    src/codec/http_message.cpp
)
target_include_directories(proxy_tests PRIVATE src /opt/homebrew/include)
target_link_libraries(proxy_tests PRIVATE
    Catch2::Catch2WithMain
)
