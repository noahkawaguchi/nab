#include "protocol_types.hpp"

#include <cctype>
#include <format>
#include <ranges>

namespace {

/// Trims whitespace and converts to lowercase.
auto normalize_str(const std::string_view sv) -> std::string {
  return sv | std::views::drop_while([](unsigned char c) { return std::isspace(c); })
         | std::views::reverse
         | std::views::drop_while([](unsigned char c) { return std::isspace(c); })
         | std::views::reverse
         | std::views::transform([](unsigned char c) { return std::tolower(c); })
         | std::ranges::to<std::string>();
}

} // namespace

namespace nab {

auto protocol_to_string(const Protocol protocol) -> std::string {
  switch (protocol) {
  case Protocol::TCP: return "TCP";
  case Protocol::UDP: return "UDP";
  case Protocol::ICMP: return "ICMP";
  case Protocol::IGMP: return "IGMP";
  case Protocol::Unknown: return "Unknown";
  // Should be impossible to reach here
  default: return "Unexpected";
  }
}

auto parse_protocol(const std::uint8_t protocol_num) -> Protocol {
  switch (protocol_num) {
  case 1: return Protocol::ICMP;
  case 2: return Protocol::IGMP;
  // NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
  case 6: return Protocol::TCP;
  case 17: return Protocol::UDP;
  // NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
  default: return Protocol::Unknown;
  }
}

auto parse_protocol(const std::string_view protocol_str) -> Protocol {
  const std::string normalized{normalize_str(protocol_str)};

  if (normalized == "tcp") { return Protocol::TCP; }
  if (normalized == "udp") { return Protocol::UDP; }
  if (normalized == "icmp") { return Protocol::ICMP; }
  if (normalized == "igmp") { return Protocol::IGMP; }

  return Protocol::Unknown;
}

auto ethertype_to_string(const EtherType ethertype) -> std::string {
  switch (ethertype) {
  case EtherType::IPv4: return "IPv4";
  case EtherType::ARP: return "ARP";
  case EtherType::IPv6: return "IPv6";
  default: return std::format("EtherType-0x{:04x}", static_cast<std::uint16_t>(ethertype));
  }
}

} // namespace nab
