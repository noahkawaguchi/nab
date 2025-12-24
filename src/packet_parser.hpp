#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include "packet_filter.hpp"

namespace nab {

// Helper function to format IP address from 4 bytes
auto format_ip_address(std::span<const uint8_t, 4> ip) -> std::string;

// Parse Ethernet header and return EtherType
// Returns std::nullopt if packet is too short
auto parse_ethernet_header(std::span<const uint8_t> packet) -> std::optional<uint16_t>;

// Parse IPv4 header and extract relevant information
// Populates the ParsedPacket structure
// Returns true if parsing succeeded
auto parse_ipv4_packet(std::span<const uint8_t> packet, ParsedPacket &parsed) -> bool;

// Check if packet is SSH (port 22)
auto is_ssh_packet(const ParsedPacket &packet) -> bool;

// Get service name for well-known ports
auto get_service_name(uint16_t port) -> std::string;

} // namespace nab
