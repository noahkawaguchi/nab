#include "protocol_types.hpp"

#include <format>

namespace nab {

auto protocol_to_string(Protocol protocol) -> std::string {
  switch (protocol) {
  case Protocol::TCP: return "TCP";
  case Protocol::UDP: return "UDP";
  case Protocol::ICMP: return "ICMP";
  case Protocol::IGMP: return "IGMP";
  case Protocol::Unknown: return "Unknown";
  }
  return "Unknown";
}

auto parse_protocol(std::uint8_t protocol_num) -> Protocol {
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

auto parse_protocol(std::string_view protocol_str) -> Protocol {
  if (protocol_str == "tcp") { return Protocol::TCP; }
  if (protocol_str == "udp") { return Protocol::UDP; }
  if (protocol_str == "icmp") { return Protocol::ICMP; }
  if (protocol_str == "igmp") { return Protocol::IGMP; }
  return Protocol::Unknown;
}

auto ethertype_to_string(EtherType ethertype) -> std::string {
  switch (ethertype) {
  case EtherType::IPv4: return "IPv4";
  case EtherType::ARP: return "ARP";
  case EtherType::IPv6: return "IPv6";
  default: return std::format("EtherType-0x{:04x}", static_cast<std::uint16_t>(ethertype));
  }
}

} // namespace nab
