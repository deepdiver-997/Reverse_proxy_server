#include "config.h"
#include <toml.hpp>
#include <spdlog/spdlog.h>

namespace ebpf_quic_proxy {

ProxyConfig load_config(const std::string& path) {
    ProxyConfig cfg;

    try {
        auto root = toml::parse(path);

        // [listen]
        if (root.contains("listen")) {
            auto& tbl = toml::find(root, "listen");
            cfg.listen_addr =
                toml::find_or<std::string>(tbl, "address", "0.0.0.0");
            cfg.listen_port =
                toml::find_or<int>(tbl, "port", 8080);
            cfg.num_threads =
                toml::find_or<int>(tbl, "num_threads", 1);
            cfg.quic_port =
                toml::find_or<int>(tbl, "quic_port", 0);
            cfg.quic_cert_file =
                toml::find_or<std::string>(tbl, "quic_cert_file",
                                           "certs/cert.pem");
            cfg.quic_key_file =
                toml::find_or<std::string>(tbl, "quic_key_file",
                                           "certs/key.pem");
        }

        // [[backends]]
        if (root.contains("backends")) {
            auto& arr = toml::find(root, "backends").as_array();
            for (auto& v : arr) {
                BackendEndpoint be;
                be.backend_id = toml::find<std::string>(v, "id");
                be.host = toml::find<std::string>(v, "host");
                be.port = toml::find<int>(v, "port");
                be.weight = toml::find_or<int>(v, "weight", 1);
                cfg.backends.push_back(std::move(be));
            }
        }

        // [[routes]]
        if (root.contains("routes")) {
            auto& arr = toml::find(root, "routes").as_array();
            for (auto& v : arr) {
                RouteRule r;
                r.host_match = toml::find<std::string>(v, "host");
                r.backend_id = toml::find<std::string>(v, "backend");
                cfg.routes.push_back(std::move(r));
            }
        }
    } catch (const std::exception& e) {
        spdlog::error("Failed to parse config {}: {}", path, e.what());
        throw;
    }

    return cfg;
}

} // namespace ebpf_quic_proxy
