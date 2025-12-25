#include <array>
#include <cstdint>
#include <span>

#include <catch2/catch_test_macros.hpp>

#include "packet_filter.hpp"
#include "packet_parser.hpp"
#include "protocol_types.hpp"

using namespace nab;

TEST_CASE("parse_ethernet_header identifies IPv4 packets", "[ethernet]") {
  // clang-format off
  static constexpr std::array<std::uint8_t, 14> packet = {
      // Destination MAC (6 bytes)
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      // Source MAC (6 bytes)
      0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
      // EtherType: 0x0800 = IPv4 (2 bytes, big-endian)
      0x08, 0x00,
  };
  // clang-format on

  const auto ethertype = parse_ethernet_header(std::span{packet});
  REQUIRE(ethertype.has_value());
  CHECK(ethertype.value() == EtherType::IPv4);
}

TEST_CASE("parse_ethernet_header identifies ARP packets", "[ethernet]") {
  // clang-format off
  static constexpr std::array<std::uint8_t, 14> packet = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Dest MAC
      0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Src MAC
      0x08, 0x06,                          // EtherType: 0x0806 = ARP
  };
  // clang-format on

  const auto ethertype = parse_ethernet_header(std::span{packet});
  REQUIRE(ethertype.has_value());
  CHECK(ethertype.value() == EtherType::ARP);
}

TEST_CASE("parse_ethernet_header rejects truncated packets", "[ethernet]") {
  // Only 10 bytes instead of required 14
  static constexpr std::array<std::uint8_t, 10> packet = {0x00, 0x11, 0x22, 0x33, 0x44,
                                                          0x55, 0xAA, 0xBB, 0xCC, 0xDD};

  CHECK_FALSE(parse_ethernet_header(std::span{packet}).has_value());
}

TEST_CASE("parse_ipv4_packet extracts source and destination IPs", "[ipv4]") {
  // clang-format off
  static constexpr std::array<std::uint8_t, 34> packet = {
      // Ethernet header (14 bytes)
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Dest MAC
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Src MAC
      0x08, 0x00,                          // EtherType: IPv4

      // IPv4 header (20 bytes minimum)
      0x45,                                // Version (4) + IHL (5 = 20 bytes)
      0x00,                                // DSCP/ECN
      0x00, 0x14,                          // Total length: 20 bytes
      0x00, 0x00,                          // Identification
      0x00, 0x00,                          // Flags + Fragment offset
      0x40,                                // TTL: 64
      0x06,                                // Protocol: 6 = TCP
      0x00, 0x00,                          // Header checksum (not validated)
      // Source IP: 192.168.1.100
      192, 168, 1, 100,
      // Destination IP: 10.0.0.1
      10, 0, 0, 1,
  };
  // clang-format on

  const auto parsed = parse_ipv4_packet(std::span{packet});
  REQUIRE(parsed.has_value());
  CHECK(parsed->src_ip == "192.168.1.100");
  CHECK(parsed->dst_ip == "10.0.0.1");
  CHECK(parsed->protocol == Protocol::TCP);
}

TEST_CASE("parse_ipv4_packet identifies different protocols", "[ipv4]") {
  // clang-format off

  // Base packet template
  std::array<std::uint8_t, 34> packet = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Dest MAC
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Src MAC
      0x08, 0x00,                          // IPv4
      0x45, 0x00, 0x00, 0x14,              // IPv4 header start
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x00,                          // TTL, Protocol (filled below)
      0x00, 0x00,                          // Checksum
      192, 168, 1, 1,                      // Src IP
      192, 168, 1, 2,                      // Dst IP
  };
  // clang-format on

  constexpr std::size_t protocol_byte = 23; // Protocol field is at byte 23

  SECTION("TCP protocol") {
    packet[protocol_byte] = 6;
    const auto parsed = parse_ipv4_packet(std::span{packet});
    REQUIRE(parsed.has_value());
    CHECK(parsed->protocol == Protocol::TCP);
  }

  SECTION("UDP protocol") {
    packet[protocol_byte] = 17;
    const auto parsed = parse_ipv4_packet(std::span{packet});
    REQUIRE(parsed.has_value());
    CHECK(parsed->protocol == Protocol::UDP);
  }

  SECTION("ICMP protocol") {
    packet[protocol_byte] = 1;
    const auto parsed = parse_ipv4_packet(std::span{packet});
    REQUIRE(parsed.has_value());
    CHECK(parsed->protocol == Protocol::ICMP);
  }
}

TEST_CASE("parse_ipv4_packet rejects truncated packets", "[ipv4]") {
  // Only Ethernet header, no IPv4 header
  static constexpr std::array<std::uint8_t, 14> packet = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
  };

  CHECK_FALSE(parse_ipv4_packet(std::span{packet}).has_value());
}

TEST_CASE("parse_ipv4_packet extracts TCP ports", "[ipv4][ports]") {
  // clang-format off
  static constexpr std::array<std::uint8_t, 54> packet = {
      // Ethernet header (14 bytes)
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x08, 0x00,

      // IPv4 header (20 bytes)
      0x45,                                // Version=4, IHL=5 (20 bytes)
      0x00,                                // DSCP/ECN
      0x00, 0x28,                          // Total length: 40 bytes (20 IP + 20 TCP)
      0x00, 0x00,                          // Identification
      0x00, 0x00,                          // Flags + Fragment offset
      0x40,                                // TTL: 64
      0x06,                                // Protocol: 6 = TCP
      0x00, 0x00,                          // Header checksum
      192, 168, 1, 1,                      // Source IP
      10, 0, 0, 1,                         // Dest IP

      // TCP header (20 bytes)
      0x04, 0xD2,                          // Source port: 1234 (0x04D2)
      0x01, 0xBB,                          // Dest port: 443 (0x01BB)
      0x00, 0x00, 0x00, 0x00,              // Sequence number
      0x00, 0x00, 0x00, 0x00,              // Ack number
      0x50, 0x00,                          // Data offset (5) + flags
      0x00, 0x00,                          // Window size
      0x00, 0x00,                          // Checksum
      0x00, 0x00,                          // Urgent pointer
  };
  // clang-format on

  const auto parsed = parse_ipv4_packet(std::span{packet});
  REQUIRE(parsed.has_value());
  REQUIRE(parsed->src_port.has_value());
  REQUIRE(parsed->dst_port.has_value());
  CHECK(parsed->src_port.value() == 1234);
  CHECK(parsed->dst_port.value() == 443);
}

TEST_CASE("parse_ipv4_packet extracts UDP ports", "[ipv4][ports]") {
  // clang-format off
  static constexpr std::array<std::uint8_t, 42> packet = {
      // Ethernet header (14 bytes)
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x08, 0x00,

      // IPv4 header (20 bytes)
      0x45,                                // Version=4, IHL=5
      0x00,                                // DSCP/ECN
      0x00, 0x1C,                          // Total length: 28 bytes (20 IP + 8 UDP)
      0x00, 0x00,                          // Identification
      0x00, 0x00,                          // Flags + Fragment offset
      0x40,                                // TTL: 64
      0x11,                                // Protocol: 17 = UDP
      0x00, 0x00,                          // Header checksum
      192, 168, 1, 100,                    // Source IP
      8, 8, 8, 8,                          // Dest IP (Google DNS)

      // UDP header (8 bytes)
      0xC3, 0x5C,                          // Source port: 50012 (0xC35C)
      0x00, 0x35,                          // Dest port: 53 (0x0035 = DNS)
      0x00, 0x08,                          // Length: 8 bytes
      0x00, 0x00,                          // Checksum
  };
  // clang-format on

  const auto parsed = parse_ipv4_packet(std::span{packet});
  REQUIRE(parsed.has_value());
  CHECK(parsed->protocol == Protocol::UDP);
  REQUIRE(parsed->src_port.has_value());
  CHECK(parsed->src_port.value() == 50012);
  REQUIRE(parsed->dst_port.has_value());
  CHECK(parsed->dst_port.value() == 53);
}

TEST_CASE("parse_ipv4_packet handles missing ports for ICMP", "[ipv4][ports]") {
  // clang-format off
  static constexpr std::array<std::uint8_t, 42> packet = {
      // Ethernet header (14 bytes)
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x08, 0x00,

      // IPv4 header (20 bytes)
      0x45,                                // Version=4, IHL=5
      0x00,                                // DSCP/ECN
      0x00, 0x1C,                          // Total length: 28 bytes
      0x00, 0x00,                          // Identification
      0x00, 0x00,                          // Flags + Fragment offset
      0x40,                                // TTL: 64
      0x01,                                // Protocol: 1 = ICMP
      0x00, 0x00,                          // Header checksum
      192, 168, 1, 1,                      // Source IP
      192, 168, 1, 100,                    // Dest IP

      // ICMP Echo Request (8 bytes)
      0x08,                                // Type: 8 = Echo Request
      0x00,                                // Code: 0
      0x00, 0x00,                          // Checksum
      0x12, 0x34,                          // Identifier
      0x00, 0x01,                          // Sequence number
  };
  // clang-format on

  const auto parsed = parse_ipv4_packet(std::span{packet});
  // Should have still parsed the packet even without ports
  REQUIRE(parsed.has_value());
  CHECK(parsed->protocol == Protocol::ICMP);
  // ICMP packets don't have ports
  CHECK_FALSE(parsed->src_port.has_value());
  CHECK_FALSE(parsed->dst_port.has_value());
}

TEST_CASE("PacketFilter matches protocol correctly", "[filter]") {
  static constexpr ParsedPacket tcp_packet = {
      .protocol = Protocol::TCP,
      .src_port = 12345,
      .dst_port = 80,
      .src_ip = "192.168.1.1",
      .dst_ip = "192.168.1.2",
  };

  SECTION("Filter matches TCP") {
    CHECK(PacketFilter{Protocol::TCP, std::nullopt, std::nullopt}.matches(tcp_packet));
  }

  SECTION("Filter rejects non-TCP") {
    CHECK_FALSE(PacketFilter{Protocol::UDP, std::nullopt, std::nullopt}.matches(tcp_packet));
  }
}

TEST_CASE("PacketFilter matches port correctly", "[filter]") {
  static constexpr ParsedPacket packet = {
      .protocol = Protocol::TCP,
      .src_port = 12345,
      .dst_port = 80,
      .src_ip = "192.168.1.1",
      .dst_ip = "192.168.1.2",
  };

  SECTION("Matches destination port") {
    CHECK(PacketFilter{std::nullopt, 80, std::nullopt}.matches(packet));
  }

  SECTION("Matches source port") {
    CHECK(PacketFilter{std::nullopt, 12345, std::nullopt}.matches(packet));
  }

  SECTION("Rejects non-matching port") {
    CHECK_FALSE(PacketFilter{std::nullopt, 443, std::nullopt}.matches(packet));
  }
}

TEST_CASE("PacketFilter matches host IP correctly", "[filter]") {
  static constexpr ParsedPacket packet = {
      .protocol = Protocol::TCP,
      .src_ip = "192.168.1.100",
      .dst_ip = "10.0.0.1",
  };

  SECTION("Matches source IP") {
    CHECK(PacketFilter{std::nullopt, std::nullopt, "192.168.1.100"}.matches(packet));
  }

  SECTION("Matches destination IP") {
    CHECK(PacketFilter{std::nullopt, std::nullopt, "10.0.0.1"}.matches(packet));
  }

  SECTION("Rejects non-matching IP") {
    CHECK_FALSE(PacketFilter{std::nullopt, std::nullopt, "8.8.8.8"}.matches(packet));
  }
}

TEST_CASE("PacketFilter combines multiple criteria", "[filter]") {
  static constexpr ParsedPacket packet = {
      .protocol = Protocol::TCP,
      .src_port = 54321,
      .dst_port = 443,
      .src_ip = "192.168.1.100",
      .dst_ip = "10.0.0.1",
  };

  SECTION("Matches when all criteria match") {
    CHECK(PacketFilter{Protocol::TCP, 443, "10.0.0.1"}.matches(packet));
  }

  SECTION("Rejects when protocol doesn't match") {
    CHECK_FALSE(PacketFilter{Protocol::UDP, 443, "10.0.0.1"}.matches(packet));
  }

  SECTION("Rejects when port doesn't match") {
    CHECK_FALSE(PacketFilter{Protocol::TCP, 80, "10.0.0.1"}.matches(packet));
  }

  SECTION("Rejects when host doesn't match") {
    CHECK_FALSE(PacketFilter{Protocol::TCP, 443, "8.8.8.8"}.matches(packet));
  }
}
