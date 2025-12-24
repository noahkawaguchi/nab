#include "packet_parser.hpp"

#include <format>

namespace nab {

auto format_ip_address(const uint8_t *ip) -> std::string {
  return std::format("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
}

auto parse_ethernet_header(const uint8_t *data, int len) -> std::optional<uint16_t> {
  if (len < 14) { return std::nullopt; }
  // EtherType is big-endian (2 bytes at offset 12-13)
  return static_cast<uint16_t>((data[12] << 8) | data[13]);
}

auto parse_ipv4_packet(const uint8_t *data, int len, ParsedPacket &packet) -> bool {
  // Need at least Ethernet (14) + IPv4 header (20)
  if (len < 34) { return false; }

  const uint8_t *ip_header{data + 14};

  // Byte 0: header length (bottom 4 bits) in 32-bit words
  const auto ihl = static_cast<uint8_t>(ip_header[0] & 0x0F);

  // Byte 9: protocol (6=TCP, 17=UDP, 1=ICMP, etc.)
  const uint8_t protocol{ip_header[9]};

  // Bytes 12-15: source IP address
  const uint8_t *src_ip{&ip_header[12]};

  // Bytes 16-19: destination IP address
  const uint8_t *dst_ip{&ip_header[16]};

  packet.src_ip = format_ip_address(src_ip);
  packet.dst_ip = format_ip_address(dst_ip);

  // Parse TCP/UDP for ports
  if (protocol == 6 || protocol == 17) {
    packet.protocol = (protocol == 6) ? "tcp" : "udp";

    const int ip_header_len{ihl * 4};
    const int transport_offset{14 + ip_header_len};
    const int min_transport_len{(protocol == 6) ? 20 : 8};

    if (len < transport_offset + min_transport_len) { return false; } // Truncated packet

    const uint8_t *transport_header{data + transport_offset};

    // Both TCP and UDP have ports at the same location
    // Bytes 0-1: source port (big-endian)
    // Bytes 2-3: destination port (big-endian)
    packet.src_port = static_cast<uint16_t>((transport_header[0] << 8) | transport_header[1]);
    packet.dst_port = static_cast<uint16_t>((transport_header[2] << 8) | transport_header[3]);
  } else if (protocol == 1) {
    packet.protocol = "icmp";
  } else if (protocol == 2) {
    packet.protocol = "igmp";
  } else {
    packet.protocol = std::format("proto-{}", protocol);
  }

  return true;
}

auto is_ssh_packet(const ParsedPacket &packet) -> bool {
  if (!packet.src_port.has_value() || !packet.dst_port.has_value()) { return false; }
  return packet.src_port.value() == 22 || packet.dst_port.value() == 22;
}

auto get_service_name(uint16_t port) -> const char * {
  switch (port) {
  case 80: return "/HTTP";
  case 443: return "/HTTPS";
  case 53: return "/DNS";
  case 22: return "/SSH";
  default: return "";
  }
}

} // namespace nab
