#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace nab {

/// Ethernet frame types (EtherType field).
enum class EtherType : std::uint16_t {
  IPv4 = 0x0800,
  ARP = 0x0806,
  IPv6 = 0x86DD,
};

/// IP protocol numbers.
enum class Protocol : std::uint8_t {
  ICMP = 1,
  IGMP = 2,
  TCP = 6,
  UDP = 17,
  Unknown = 255,
};

/// Converts `Protocol` enum to string for display.
auto protocol_to_string(Protocol protocol) -> std::string;

/// Parses protocol number to `Protocol` enum.
auto parse_protocol(std::uint8_t protocol_num) -> Protocol;

/// Parses protocol string to `Protocol` enum.
auto parse_protocol(std::string_view protocol_str) -> Protocol;

/// Converts `EtherType` enum to string for display.
auto ether_type_to_string(EtherType ether_type) -> std::string;

} // namespace nab
