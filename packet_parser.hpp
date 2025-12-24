#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "packet_filter.hpp"

namespace nab {

// Helper function to format IP address from 4 bytes
auto format_ip_address(const uint8_t *ip) -> std::string;

// Parse Ethernet header and return EtherType
// Returns std::nullopt if packet is too short
auto parse_ethernet_header(const uint8_t *data, int len) -> std::optional<uint16_t>;

// Parse IPv4 header and extract relevant information
// Populates the ParsedPacket structure
// Returns true if parsing succeeded
auto parse_ipv4_packet(const uint8_t *data, int len, ParsedPacket &packet) -> bool;

// Check if packet is SSH (port 22)
auto is_ssh_packet(const ParsedPacket &packet) -> bool;

// Get service name for well-known ports
auto get_service_name(uint16_t port) -> const char *;

} // namespace nab
