#include "config.h"
#include <catch2/catch_test_macros.hpp>
#include <fstream>

using namespace ebpf_quic_proxy;

namespace {

std::string write_temp_toml(const std::string& body) {
    std::string path = "/tmp/proxy_cfg_test.toml";
    std::ofstream f(path);
    f << body;
    f.close();
    return path;
}

} // namespace

TEST_CASE("config: backend protocol defaults to h1 (TCP)", "[config]") {
    auto path = write_temp_toml(
        "[listen]\n"
        "port = 8080\n"
        "\n"
        "[[backends]]\n"
        "id = \"app1\"\n"
        "host = \"127.0.0.1\"\n"
        "port = 9001\n");

    auto cfg = load_config(path);
    REQUIRE(cfg.backends.size() == 1);
    REQUIRE(cfg.backends[0].protocol == TransportProtocol::TCP);
}

TEST_CASE("config: protocol = \"h3\" selects QUIC upstream", "[config]") {
    auto path = write_temp_toml(
        "[listen]\n"
        "port = 8080\n"
        "\n"
        "[[backends]]\n"
        "id = \"app_h3\"\n"
        "host = \"127.0.0.1\"\n"
        "port = 19000\n"
        "protocol = \"h3\"\n");

    auto cfg = load_config(path);
    REQUIRE(cfg.backends.size() == 1);
    REQUIRE(cfg.backends[0].protocol == TransportProtocol::QUIC);
}

TEST_CASE("config: dual_stack defaults to false", "[config]") {
    auto path = write_temp_toml("[listen]\nport = 8080\n");
    auto cfg = load_config(path);
    REQUIRE_FALSE(cfg.dual_stack);
}

TEST_CASE("config: dual_stack = true is parsed", "[config]") {
    auto path = write_temp_toml(
        "[listen]\n"
        "port = 8080\n"
        "dual_stack = true\n");
    auto cfg = load_config(path);
    REQUIRE(cfg.dual_stack);
}

TEST_CASE("config: mixed h1/h3 backends", "[config]") {
    auto path = write_temp_toml(
        "[listen]\n"
        "port = 8080\n"
        "\n"
        "[[backends]]\n"
        "id = \"app1\"\n"
        "host = \"127.0.0.1\"\n"
        "port = 9001\n"
        "\n"
        "[[backends]]\n"
        "id = \"app_h3\"\n"
        "host = \"127.0.0.1\"\n"
        "port = 19000\n"
        "protocol = \"h3\"\n");

    auto cfg = load_config(path);
    REQUIRE(cfg.backends.size() == 2);
    REQUIRE(cfg.backends[0].protocol == TransportProtocol::TCP);
    REQUIRE(cfg.backends[1].protocol == TransportProtocol::QUIC);
}
