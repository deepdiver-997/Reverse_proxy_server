#pragma once

#include "codec/http_message.h"
#include <string>
#include <vector>

namespace ebpf_quic_proxy {

class Router {
public:
    struct Rule {
        std::string host_match; // "*" for default
        std::string backend_id;
    };

    void add_rule(Rule r);
    void add_rule(const std::string& host_match,
                  const std::string& backend_id);

    /// Match request to backend_id.
    /// Returns empty string if no match (caller should 503).
    std::string route(const HttpRequestHead& req) const;

private:
    std::vector<Rule> rules_;
};

} // namespace ebpf_quic_proxy
