#include "packet_parser.hpp"

#include <cstddef>
#include <cstdint>
#include <format>

#include "protocol_types.hpp"

namespace {

constexpr std::size_t ETHERNET_BYTES{14};
constexpr std::size_t IPV4_BYTES{20};

constexpr std::uint16_t HTTP_PORT{80};
constexpr std::uint16_t HTTPS_PORT{443};
constexpr std::uint16_t DNS_PORT{53};
constexpr std::uint16_t SSH_PORT{22};

} // namespace

namespace nab {

auto format_ip_address(const std::span<const std::uint8_t, 4> ip) -> std::string {
  return std::format("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
}

auto parse_ethernet_header(const std::span<const std::uint8_t> packet) -> std::optional<EtherType> {
  if (packet.size() < ETHERNET_BYTES) { return std::nullopt; }
  // EtherType is big-endian (2 bytes at offset 12-13)
  return static_cast<EtherType>((packet[12] << 8) | packet[13]);
}

auto parse_ipv4_packet(const std::span<const std::uint8_t> packet, ParsedPacket &parsed) -> bool {
  // Need at least Ethernet + IPv4 header
  if (packet.size() < ETHERNET_BYTES + IPV4_BYTES) { return false; }

  // IP header starts after Ethernet header
  const auto ip_header = packet.subspan(ETHERNET_BYTES);

  // Byte 0: header length (bottom 4 bits) in 32-bit words
  const auto ihl = static_cast<std::uint8_t>(ip_header[0] & 0x0F);

  // Byte 9: protocol (6=TCP, 17=UDP, 1=ICMP, etc.)
  const std::uint8_t protocol{ip_header[9]};

  // Bytes 12-15: source IP address (4 bytes)
  const auto src_ip = ip_header.subspan<12, 4>();

  // Bytes 16-19: destination IP address (4 bytes)
  const auto dst_ip = ip_header.subspan<16, 4>();

  parsed.src_ip = format_ip_address(src_ip);
  parsed.dst_ip = format_ip_address(dst_ip);
  parsed.protocol = parse_protocol(protocol);

  // Parse TCP/UDP for ports
  if (parsed.protocol == Protocol::TCP || parsed.protocol == Protocol::UDP) {
    const auto ip_header_len = static_cast<const std::size_t>(ihl * 4);
    const std::size_t transport_offset{14 + ip_header_len};
    const auto min_transport_len = static_cast<std::size_t>((protocol == 6) ? 20 : 8);

    // Truncated packet
    if (packet.size() < transport_offset + min_transport_len) { return false; }

    // Transport header starts after IP header
    const auto transport_header = packet.subspan(transport_offset);

    // Both TCP and UDP have ports at the same location
    // Bytes 0-1: source port (big-endian)
    // Bytes 2-3: destination port (big-endian)
    parsed.src_port = static_cast<std::uint16_t>((transport_header[0] << 8) | transport_header[1]);
    parsed.dst_port = static_cast<std::uint16_t>((transport_header[2] << 8) | transport_header[3]);
  }

  return true;
}

auto is_ssh_packet(const ParsedPacket &packet) -> bool {
  if (!packet.src_port.has_value() || !packet.dst_port.has_value()) { return false; }
  return packet.src_port.value() == SSH_PORT || packet.dst_port.value() == SSH_PORT;
}

auto get_service_name(const std::uint16_t port) -> std::string {
  switch (port) {
  case HTTP_PORT: return "/HTTP";
  case HTTPS_PORT: return "/HTTPS";
  case DNS_PORT: return "/DNS";
  case SSH_PORT: return "/SSH";
  default: return "";
  }
}

} // namespace nab
