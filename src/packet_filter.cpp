#include "packet_filter.hpp"

#include <format>

#include "protocol_types.hpp"

namespace nab {

auto PacketFilter::matches(const ParsedPacket &packet) const -> bool {
  // Check protocol filter
  if (protocol_.has_value() && packet.protocol != protocol_.value()) { return false; }

  // Check port filter (matches source OR destination)
  if (port_.has_value()) {
    bool port_matches = false;
    if (packet.src_port.has_value() && packet.src_port.value() == port_.value()) {
      port_matches = true;
    }
    if (packet.dst_port.has_value() && packet.dst_port.value() == port_.value()) {
      port_matches = true;
    }
    if (!port_matches) { return false; }
  }

  // Check host filter (matches source OR destination)
  if (host_.has_value()) {
    bool host_matches = false;
    if (packet.src_ip.has_value() && packet.src_ip.value() == host_.value()) {
      host_matches = true;
    }
    if (packet.dst_ip.has_value() && packet.dst_ip.value() == host_.value()) {
      host_matches = true;
    }
    if (!host_matches) { return false; }
  }

  return true;
}

auto PacketFilter::description() const -> std::string {
  std::string desc = "Active filter(s):";
  if (protocol_.has_value()) {
    desc += std::format(" protocol={}", protocol_to_string(protocol_.value()));
  }
  if (port_.has_value()) { desc += std::format(" port={}", port_.value()); }
  if (host_.has_value()) { desc += std::format(" host={}", host_.value()); }
  return desc;
}

} // namespace nab
