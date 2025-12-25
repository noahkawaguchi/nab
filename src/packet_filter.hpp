#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "protocol_types.hpp"

namespace nab {

/// Parsed packet information needed for filtering.
struct ParsedPacket {
  Protocol protocol{Protocol::Unknown};
  std::optional<std::uint16_t> src_port;
  std::optional<std::uint16_t> dst_port;
  std::optional<std::string> src_ip;
  std::optional<std::string> dst_ip;
};

/// Filter criteria for packet capture.
class PacketFilter {
public:
  PacketFilter(std::optional<Protocol> protocol, std::optional<std::uint16_t> port,
               std::optional<std::string> host)
      : protocol_(protocol), port_(port), host_(std::move(host)){};

  /// Checks whether any of the filters are active.
  [[nodiscard]] auto has_any_filter() const -> bool {
    return protocol_.has_value() || port_.has_value() || host_.has_value();
  }

  /// Checks if a packet matches the filter criteria, returning true if packet passes (should be
  /// captured/displayed).
  [[nodiscard]] auto matches(const ParsedPacket &packet) const -> bool;

  /// Generates filter description for display.
  [[nodiscard]] auto description() const -> std::string;

private:
  std::optional<Protocol> protocol_;
  std::optional<std::uint16_t> port_;
  std::optional<std::string> host_;
};

} // namespace nab
