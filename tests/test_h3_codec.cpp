#include "codec/h3_codec.h"
#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <vector>

using namespace ebpf_quic_proxy;

// ═══════════════════════════════════════════════════════════
// varint encode/decode round-trip
// ═══════════════════════════════════════════════════════════

TEST_CASE("varint round-trip", "[h3_codec]") {
    auto check = [](uint64_t value) {
        uint8_t buf[8] = {};
        std::size_t n = encode_varint(value, buf);
        REQUIRE(n > 0);
        REQUIRE(n == varint_size(value));

        auto result = decode_varint(buf, n);
        REQUIRE(result.bytes_read == n);
        REQUIRE(result.value == value);
    };

    check(0);
    check(1);
    check(63);       // max 1-byte
    check(64);       // min 2-byte
    check(16383);    // max 2-byte
    check(16384);    // min 4-byte
    check(1073741823); // max 4-byte
    check(1073741824ull); // min 8-byte
    check(4611686018427387903ull); // max value
}

TEST_CASE("varint boundary values", "[h3_codec]") {
    // 1-byte values.
    REQUIRE(varint_size(0) == 1);
    REQUIRE(varint_size(63) == 1);

    // 2-byte values.
    REQUIRE(varint_size(64) == 2);
    REQUIRE(varint_size(16383) == 2);

    // 4-byte values.
    REQUIRE(varint_size(16384) == 4);
    REQUIRE(varint_size(1073741823) == 4);

    // 8-byte values.
    REQUIRE(varint_size(1073741824ull) == 8);
}

TEST_CASE("decode_varint handles short buffer", "[h3_codec]") {
    uint8_t buf[] = {0x40}; // 2-byte encoding, only 1 byte provided
    auto result = decode_varint(buf, 1);
    REQUIRE(result.bytes_read == 0); // needs more data
}

// ═══════════════════════════════════════════════════════════
// literal header parsing
// ═══════════════════════════════════════════════════════════

TEST_CASE("parse_request_headers basic", "[h3_codec]") {
    // Build a literal headers payload for:
    //   :method = GET
    //   :path = /api
    //   :authority = example.com
    std::vector<uint8_t> payload;

    auto add = [&](const std::string& name, const std::string& value) {
        uint8_t buf[8];
        std::size_t ns = encode_varint(name.size(), buf);
        payload.insert(payload.end(), buf, buf + ns);
        payload.insert(payload.end(),
                       reinterpret_cast<const uint8_t*>(name.data()),
                       reinterpret_cast<const uint8_t*>(name.data()) +
                           name.size());
        std::size_t vs = encode_varint(value.size(), buf);
        payload.insert(payload.end(), buf, buf + vs);
        payload.insert(payload.end(),
                       reinterpret_cast<const uint8_t*>(value.data()),
                       reinterpret_cast<const uint8_t*>(value.data()) +
                           value.size());
    };

    add(":method", "GET");
    add(":path", "/api");
    add(":authority", "example.com");
    add("content-length", "42");

    std::string method, path;
    HeaderMap hdrs;
    std::optional<std::size_t> cl;

    bool ok = h3_detail::parse_request_headers(
        payload.data(), payload.size(), method, path, hdrs, cl);
    REQUIRE(ok);
    REQUIRE(method == "GET");
    REQUIRE(path == "/api");
    REQUIRE(hdrs.get("host").value_or("") == "example.com");
    REQUIRE(cl == 42u);
}

TEST_CASE("parse_request_headers ignores unknown pseudo", "[h3_codec]") {
    std::vector<uint8_t> payload;
    auto add = [&](const std::string& n, const std::string& v) {
        uint8_t buf[8];
        std::size_t ns = encode_varint(n.size(), buf);
        payload.insert(payload.end(), buf, buf + ns);
        payload.insert(payload.end(),
                       reinterpret_cast<const uint8_t*>(n.data()),
                       reinterpret_cast<const uint8_t*>(n.data()) + n.size());
        std::size_t vs = encode_varint(v.size(), buf);
        payload.insert(payload.end(), buf, buf + vs);
        payload.insert(payload.end(),
                       reinterpret_cast<const uint8_t*>(v.data()),
                       reinterpret_cast<const uint8_t*>(v.data()) + v.size());
    };

    add(":method", "POST");
    add(":path", "/submit");
    add(":scheme", "https");     // ignored — doesn't start with ':'
    add("x-custom", "hello");    // user header, passed through

    std::string method, path;
    HeaderMap hdrs;
    std::optional<std::size_t> cl;

    bool ok = h3_detail::parse_request_headers(
        payload.data(), payload.size(), method, path, hdrs, cl);
    REQUIRE(ok);
    REQUIRE(method == "POST");
    REQUIRE(path == "/submit");
    // :scheme is not a recognized pseudo; since it starts with ':', it's skipped.
    REQUIRE(hdrs.get(":scheme").has_value() == false);
    REQUIRE(hdrs.get("x-custom").value_or("") == "hello");
}
