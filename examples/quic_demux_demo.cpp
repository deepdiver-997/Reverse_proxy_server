// quic_demux_demo — minimal prototype of the CID-based demux for Model B.
//
// Validates the piece we propose to move OUT of lsquic and run ourselves:
//   level-1 routing  DCID -> engine  (global table, migration-safe)
// while lsquic keeps level-2 routing  DCID -> connection -> ctx  inside packet_in.
//
// Shows:
//   1. lsquic_dcid_from_packet() really parses the DCID out of a packet.
//   2. an ESTABLISHED connection routes by CID, so a 4-tuple change (Wi-Fi ->
//      cellular) does NOT move it to another engine (migration safety).
//   3. NEW connections route by hashing the source address (the DCID is
//      client-chosen and unknown at first contact).
//   4. closing a connection removes its CID->engine entry (the connection
//      wrapper carries the CID for exactly this cleanup).
//
// Compile/run: cmake --build build --target quic_demux_demo && ./build/quic_demux_demo

#include <lsquic.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

// ── Synthetic QUIC Initial packet (RFC 9000 §17.2 long header) ──
// Byte0 = 0xC0 (header form=1, fixed bit=1, type=Initial=00, spare=0000),
// then version (4B), DCID len (1B), DCID, SCID len (1B), SCID.
std::vector<uint8_t> make_initial_packet(const std::string& dcid,
                                         const std::string& scid) {
    std::vector<uint8_t> p;
    p.push_back(0xC0);
    p.push_back(0x00); p.push_back(0x00); p.push_back(0x00); p.push_back(0x01); // QUIC v1
    p.push_back(static_cast<uint8_t>(dcid.size()));
    p.insert(p.end(), dcid.begin(), dcid.end());
    p.push_back(static_cast<uint8_t>(scid.size()));
    p.insert(p.end(), scid.begin(), scid.end());
    return p;
}

std::string hex(const uint8_t* b, size_t n) {
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        char t[4];
        std::snprintf(t, sizeof(t), "%02x", b[i]);
        s += t;
    }
    return s;
}

// ── The demux (level-1 routing: DCID -> engine slot) ──

struct Demux {
    int n_slots;
    std::vector<int> slot_packets; // how many packets each slot received
    std::map<std::string, int> cid_to_slot;  // DCID (hex) -> engine slot
    const unsigned kServerCidLen = 8;

    explicit Demux(int n) : n_slots(n), slot_packets(n, 0) {}

    int hash_slot(const std::string& key) const {
        // FNV-1a — deterministic, spreads across slots.
        uint64_t h = 0xcbf29ce484222325ull;
        for (char c : key) { h ^= static_cast<uint8_t>(c); h *= 0x100000001b3ull; }
        return static_cast<int>(h % static_cast<uint64_t>(n_slots));
    }

    /// Route one packet to a slot; `src_addr` is used only for NEW connections.
    /// Returns the slot index.
    int route(const uint8_t* buf, size_t len, const std::string& src_addr,
              std::string* dcid_out) {
        uint8_t cid_len = 0;
        int off = lsquic_dcid_from_packet(buf, len, kServerCidLen, &cid_len);
        if (off < 0 || cid_len == 0) {
            std::printf("  [demux] cannot parse DCID (short-header? unknown CID len) — drop\n");
            return -1;
        }
        std::string cid = hex(buf + off, cid_len);
        if (dcid_out)
            *dcid_out = cid;

        auto it = cid_to_slot.find(cid);
        if (it != cid_to_slot.end()) {
            // Established connection: route by CID — the 4-tuple is irrelevant,
            // so a migrated connection stays on its engine.
            std::printf("  [demux] CID %s (known) -> slot %d\n", cid.c_str(),
                        it->second);
            slot_packets[it->second]++;
            return it->second;
        }

        // New connection: the DCID is client-chosen and unknown — pick an engine
        // by hashing the source address, then remember the CID -> engine.
        int slot = hash_slot(src_addr);
        cid_to_slot[cid] = slot;
        std::printf("  [demux] CID %s (NEW) -> slot %d (src %s hash)\n",
                    cid.c_str(), slot, src_addr.c_str());
        slot_packets[slot]++;
        return slot;
    }

    /// Connection closed: the connection wrapper carried its CID so we can
    /// remove the entry here (else a later packet with the same CID would be
    /// misrouted as "known").
    void close_connection(const std::string& cid_hex) {
        auto n = cid_to_slot.erase(cid_hex);
        std::printf("  [demux] connection closed, removed CID %s (%zu entries left)\n",
                    cid_hex.c_str(), cid_to_slot.size());
        (void)n;
    }
};

int main() {
    std::printf("=== QUIC demux prototype (level-1 routing: CID -> engine) ===\n\n");
    Demux demux(/*n_slots=*/2);

    // 1) Packet 1: client1 on Wi-Fi, CID = AAAA.
    auto p1 = make_initial_packet("AAAA", "servercid");
    std::printf("packet1  src=client1@wifi\n");
    std::string cid;
    int s1 = demux.route(p1.data(), p1.size(), "client1@wifi", &cid);
    std::printf("  parsed DCID = %s\n", cid.c_str());

    // 2) Same connection MIGRATES to cellular: same CID, different 4-tuple.
    std::printf("\npacket2  src=client1@cell  (MIGRATION, same CID)\n");
    int s2 = demux.route(p1.data(), p1.size(), "client1@cell", &cid);
    std::printf("  parsed DCID = %s\n", cid.c_str());
    std::printf("  migration safe? %s (slot %d == slot %d)\n",
                (s1 == s2 && s1 >= 0) ? "YES" : "NO", s1, s2);

    // 3) A different client from a different address -> hopefully another slot.
    auto p2 = make_initial_packet("BBBB", "servercid");
    std::printf("\npacket3  src=client2@wifi (different CID)\n");
    int s3 = demux.route(p2.data(), p2.size(), "client2@wifi", &cid);
    std::printf("  parsed DCID = %s\n", cid.c_str());
    std::printf("  load balancing? %s (slot %d vs %d)\n",
                (s3 != s1) ? "YES (spread)" : "same slot (hash collision is ok)", s3, s1);

    // 4) More packets on the migrated connection keep landing on its slot.
    std::printf("\npacket4  src=client1@cell (established, short 4-tuple drift)\n");
    int s4 = demux.route(p1.data(), p1.size(), "client1@cell:different_port", &cid);
    std::printf("  still on slot %d? %s\n", s1, (s4 == s1) ? "YES" : "NO");

    // 5) Close the connection -> entry removed -> a NEW connection reusing the
    //    same CID from a different source is treated as fresh.
    std::printf("\n--- connection AAAA closes ---\n");
    // The 4-byte CID "AAAA" is hex 0x41414141 ("41414141"); the connection
    // wrapper carried this value so the demux could remove its entry.
    demux.close_connection("41414141");

    std::printf("\npacket5  src=client3@wifi, CID AAAA again (post-close)\n");
    int s5 = demux.route(p1.data(), p1.size(), "client3@wifi", &cid);
    std::printf("  treated as NEW (slot %d)\n", s5);

    std::printf("\n=== slot packet counts: %d / %d ===\n", demux.slot_packets[0],
                demux.slot_packets[1]);
    return 0;
}
