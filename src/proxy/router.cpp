#include "router.h"
#include <algorithm>
#include <cctype>

namespace ebpf_quic_proxy {

void Router::add_rule(Rule r) { rules_.push_back(std::move(r)); }

void Router::add_rule(const std::string& host_match,
                      const std::string& backend_id) {
    rules_.push_back({host_match, backend_id});
}

std::string Router::route(const HttpRequestHead& req) const {
    // Extract Host header.
    auto host_opt = req.headers.get("host");
    std::string host = host_opt.value_or("");

    // Try exact match first.
    for (const auto& r : rules_) {
        if (r.host_match == host)
            return r.backend_id;
    }

    // Try wildcard.
    for (const auto& r : rules_) {
        if (r.host_match == "*")
            return r.backend_id;
    }

    return {};
}

} // namespace ebpf_quic_proxy
