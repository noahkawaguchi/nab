#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace nab {

// Parsed packet information needed for filtering
struct ParsedPacket {
  std::string protocol; // "tcp", "udp", "icmp", "arp", "ipv6", etc.
  std::optional<uint16_t> src_port;
  std::optional<uint16_t> dst_port;
  std::optional<std::string> src_ip;
  std::optional<std::string> dst_ip;
};

// Filter criteria for packet capture
class PacketFilter {
public:
  PacketFilter() = default;

  void set_protocol(const std::string &protocol) { protocol_ = protocol; }
  void set_port(uint16_t port) { port_ = port; }
  void set_host(const std::string &host) { host_ = host; }

  [[nodiscard]] auto has_any_filter() const -> bool {
    return protocol_.has_value() || port_.has_value() || host_.has_value();
  }

  // Check if a packet matches the filter criteria
  // Returns true if packet passes (should be captured/displayed)
  [[nodiscard]] auto matches(const ParsedPacket &packet) const -> bool;

  // Get filter description for display
  [[nodiscard]] auto description() const -> std::string;

private:
  std::optional<std::string> protocol_;
  std::optional<uint16_t> port_;
  std::optional<std::string> host_;
};

} // namespace nab
