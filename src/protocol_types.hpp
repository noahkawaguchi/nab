#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace nab {

/// Ethernet frame types (EtherType field).
enum class EtherType : std::uint16_t {
  Ipv4 = 0x0800,
  Arp  = 0x0806,
  Ipv6 = 0x86DD,
};

/// IP protocol numbers.
enum class Protocol : std::uint8_t {
  Icmp    = 1,
  Igmp    = 2,
  Tcp     = 6,
  Udp     = 17,
  Unknown = 255,
};

/// Converts `Protocol` enum to string view for display.
auto protocol_to_string(Protocol protocol) -> std::string_view;

/// Parses protocol number to `Protocol` enum.
auto parse_protocol(std::uint8_t protocol_num) -> Protocol;

/// Parses protocol string to `Protocol` enum.
auto parse_protocol(std::string_view protocol_str) -> Protocol;

/// Converts `EtherType` enum to string for display.
auto ether_type_to_string(EtherType ether_type) -> std::string;

} // namespace nab
