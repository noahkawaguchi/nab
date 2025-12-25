#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include "packet_filter.hpp"
#include "protocol_types.hpp"

namespace nab {

/// Formats IP address from 4 bytes.
auto format_ip_address(std::span<const std::uint8_t, 4> ip) -> std::string;

/// Parses Ethernet header and returns `EtherType`, or `std::nullopt` if the packet is too short.
auto parse_ethernet_header(std::span<const std::uint8_t> packet) -> std::optional<EtherType>;

/// Parses IPv4 header, extracts relevant information, populates the `ParsedPacket`, and returns
/// true if parsing succeeded.
auto parse_ipv4_packet(std::span<const std::uint8_t> packet, ParsedPacket &parsed) -> bool;

/// Checks if packet is SSH (port 22).
auto is_ssh_packet(const ParsedPacket &packet) -> bool;

/// Gets service name for well-known ports.
auto get_service_name(std::uint16_t port) -> std::string;

} // namespace nab
