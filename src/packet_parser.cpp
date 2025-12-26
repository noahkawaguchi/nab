#include "packet_parser.hpp"

#include <cstddef>
#include <cstdint>
#include <format>
#include <utility>

#include "protocol_types.hpp"

namespace {

constexpr std::size_t ETHERNET_BYTES{14};
constexpr std::size_t IPV4_MIN_BYTES{20};
constexpr std::size_t TCP_MIN_BYTES{20};
constexpr std::size_t UDP_BYTES{8};

enum class PortNumber : std::uint16_t {
  SSH = 22,
  DNS = 53,
  HTTP = 80,
  HTTPS = 443,
};

} // namespace

namespace nab {

auto format_ip_addr(const std::span<const std::uint8_t, 4> ip) -> std::string {
  return std::format("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
}

auto parse_ethernet_header(const std::span<const std::uint8_t> packet) -> std::optional<EtherType> {
  if (packet.size() < ETHERNET_BYTES) { return std::nullopt; }

  // EtherType is big-endian (2 bytes at offset 12-13)
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
  return static_cast<EtherType>((packet[12] << 8) | packet[13]);
}

auto parse_ipv4_packet(const std::span<const std::uint8_t> packet) -> std::optional<ParsedPacket> {
  // Need at least Ethernet + IPv4 header
  if (packet.size() < ETHERNET_BYTES + IPV4_MIN_BYTES) { return std::nullopt; }

  // IP header starts after Ethernet header
  const auto ip_header = packet.subspan(ETHERNET_BYTES);

  // Byte 0: header length (bottom 4 bits) in 32-bit words
  const auto internet_header_len = static_cast<std::uint8_t>(ip_header[0] & 0x0F);

  ParsedPacket parsed;

  // NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

  // Byte 9: protocol (6=TCP, 17=UDP, 1=ICMP, etc.)
  parsed.protocol = parse_protocol(ip_header[9]);

  // Bytes 12-15: source IP address (4 bytes)
  parsed.src_ip = format_ip_addr(ip_header.subspan<12, 4>());

  // Bytes 16-19: destination IP address (4 bytes)
  parsed.dst_ip = format_ip_addr(ip_header.subspan<16, 4>());

  // Parse TCP/UDP for ports (if enough data is present)
  if (parsed.protocol == Protocol::TCP || parsed.protocol == Protocol::UDP) {
    // Calculate IP header length (20-60 bytes). IHL is 5-15 32-bit words, so convert to bytes.
    const auto ip_header_len = static_cast<std::size_t>(internet_header_len * 4);

    // Skip over Ethernet header and IP header to get to transport header
    const std::size_t transport_offset{ETHERNET_BYTES + ip_header_len};

    // Minimum transport header size depends on TCP vs. UDP
    const auto min_transport_len =
        static_cast<std::size_t>((parsed.protocol == Protocol::TCP) ? TCP_MIN_BYTES : UDP_BYTES);

    // Only parse transport header if there is enough data (leave ports as nullopt if truncated)
    if (packet.size() >= transport_offset + min_transport_len) {
      // Transport header starts after IP header
      const auto transport_header = packet.subspan(transport_offset);

      // Both TCP and UDP have ports at the same location
      // Bytes 0-1: source port (big-endian)
      // Bytes 2-3: destination port (big-endian)
      parsed.src_port =
          static_cast<std::uint16_t>((transport_header[0] << 8) | transport_header[1]);
      parsed.dst_port =
          static_cast<std::uint16_t>((transport_header[2] << 8) | transport_header[3]);

      // NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }
  }

  return parsed;
}

auto is_ssh_packet(const ParsedPacket &packet) -> bool {
  constexpr auto ssh = std::to_underlying(PortNumber::SSH);

  // Both ports should be present to be classified as SSH traffic
  return (packet.src_port && packet.dst_port)
         && (*packet.src_port == ssh || *packet.dst_port == ssh);
}

auto get_service_name(const std::uint16_t port) -> std::string {
  switch (static_cast<PortNumber>(port)) {
  case PortNumber::HTTP: return "/HTTP";
  case PortNumber::HTTPS: return "/HTTPS";
  case PortNumber::DNS: return "/DNS";
  case PortNumber::SSH: return "/SSH";
  default: return "";
  }
}

} // namespace nab
