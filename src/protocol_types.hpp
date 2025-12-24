#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace nab {

// Ethernet frame types (EtherType field)
enum class EtherType : std::uint16_t {
  IPv4 = 0x0800,
  ARP = 0x0806,
  IPv6 = 0x86DD,
};

// IP protocol numbers
enum class Protocol : std::uint8_t {
  ICMP = 1,
  IGMP = 2,
  TCP = 6,
  UDP = 17,
  Unknown = 255,
};

// Convert Protocol enum to string for display
auto protocol_to_string(Protocol protocol) -> std::string;

// Parse protocol number to Protocol enum
auto parse_protocol(std::uint8_t protocol_num) -> Protocol;

// Parse protocol name string to Protocol enum
auto parse_protocol(std::string_view protocol_str) -> Protocol;

// Convert EtherType enum to string for display
auto ethertype_to_string(EtherType ethertype) -> std::string;

} // namespace nab
