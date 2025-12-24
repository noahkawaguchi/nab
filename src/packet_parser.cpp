#include "packet_parser.hpp"

#include <cstddef>
#include <format>

namespace nab {

auto format_ip_address(std::span<const uint8_t, 4> ip) -> std::string {
  return std::format("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
}

auto parse_ethernet_header(std::span<const uint8_t> packet) -> std::optional<uint16_t> {
  if (packet.size() < 14) { return std::nullopt; }
  // EtherType is big-endian (2 bytes at offset 12-13)
  return static_cast<uint16_t>((packet[12] << 8) | packet[13]);
}

auto parse_ipv4_packet(std::span<const uint8_t> packet, ParsedPacket &parsed) -> bool {
  // Need at least Ethernet (14) + IPv4 header (20)
  if (packet.size() < 34) { return false; }

  // IP header starts after Ethernet header (14 bytes)
  const auto ip_header = packet.subspan(14);

  // Byte 0: header length (bottom 4 bits) in 32-bit words
  const auto ihl = static_cast<uint8_t>(ip_header[0] & 0x0F);

  // Byte 9: protocol (6=TCP, 17=UDP, 1=ICMP, etc.)
  const uint8_t protocol{ip_header[9]};

  // Bytes 12-15: source IP address (4 bytes)
  const auto src_ip = ip_header.subspan<12, 4>();

  // Bytes 16-19: destination IP address (4 bytes)
  const auto dst_ip = ip_header.subspan<16, 4>();

  parsed.src_ip = format_ip_address(src_ip);
  parsed.dst_ip = format_ip_address(dst_ip);

  // Parse TCP/UDP for ports
  if (protocol == 6 || protocol == 17) {
    parsed.protocol = (protocol == 6) ? "tcp" : "udp";

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
    parsed.src_port = static_cast<uint16_t>((transport_header[0] << 8) | transport_header[1]);
    parsed.dst_port = static_cast<uint16_t>((transport_header[2] << 8) | transport_header[3]);
  } else if (protocol == 1) {
    parsed.protocol = "icmp";
  } else if (protocol == 2) {
    parsed.protocol = "igmp";
  } else {
    parsed.protocol = std::format("proto-{}", protocol);
  }

  return true;
}

auto is_ssh_packet(const ParsedPacket &packet) -> bool {
  if (!packet.src_port.has_value() || !packet.dst_port.has_value()) { return false; }
  return packet.src_port.value() == 22 || packet.dst_port.value() == 22;
}

auto get_service_name(const uint16_t port) -> std::string {
  switch (port) {
  case 80: return "/HTTP";
  case 443: return "/HTTPS";
  case 53: return "/DNS";
  case 22: return "/SSH";
  default: return "";
  }
}

} // namespace nab
