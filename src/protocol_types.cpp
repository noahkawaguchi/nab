#include "protocol_types.hpp"

#include <cctype>
#include <cstdint>
#include <format>
#include <ranges>
#include <string>
#include <string_view>

namespace {

/// Trims whitespace and converts to lowercase.
auto normalize_str(const std::string_view sv) -> std::string {
  namespace vw = std::views;
  using uchar  = const unsigned char;

  return sv | vw::drop_while([](uchar c) -> bool { return std::isspace(c) != 0; }) | vw::reverse
    | vw::drop_while([](uchar c) -> bool { return std::isspace(c) != 0; }) | vw::reverse
    | vw::transform([](uchar c) -> char { return static_cast<char>(std::tolower(c)); })
    | std::ranges::to<std::string>();
}

} // namespace

namespace nab {

auto protocol_to_string(const Protocol protocol) -> std::string_view {
  switch (protocol) {
  case Protocol::Tcp:     return "TCP";
  case Protocol::Udp:     return "UDP";
  case Protocol::Icmp:    return "ICMP";
  case Protocol::Igmp:    return "IGMP";
  case Protocol::Unknown: return "Unknown";
  default:                return "Unexpected"; // Should be impossible to reach the default
  }
}

auto parse_protocol(const std::uint8_t protocol_num) -> Protocol {
  switch (protocol_num) {
  case 1: return Protocol::Icmp;
  case 2: return Protocol::Igmp;
  // NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
  case 6:  return Protocol::Tcp;
  case 17: return Protocol::Udp;
  // NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
  default: return Protocol::Unknown;
  }
}

auto parse_protocol(const std::string_view protocol_str) -> Protocol {
  const std::string normalized{normalize_str(protocol_str)};

  if (normalized == "tcp") { return Protocol::Tcp; }
  if (normalized == "udp") { return Protocol::Udp; }
  if (normalized == "icmp") { return Protocol::Icmp; }
  if (normalized == "igmp") { return Protocol::Igmp; }

  return Protocol::Unknown;
}

auto ether_type_to_string(const EtherType ether_type) -> std::string {
  switch (ether_type) {
  case EtherType::Ipv4: return "IPv4";
  case EtherType::Arp:  return "ARP";
  case EtherType::Ipv6: return "IPv6";
  default:
    const auto raw = static_cast<std::uint16_t>(ether_type);
    return std::format("EtherType-0x{:04x}", raw);
  }
}

} // namespace nab
