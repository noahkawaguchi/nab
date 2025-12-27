#include <array>
#include <cstdint>
#include <span>

#include <catch2/catch_test_macros.hpp>

#include "packet_parser.hpp"
#include "protocol_types.hpp"

using namespace nab;

TEST_CASE("parse_ethernet_header identifies IPv4 packets", "[ethernet]") {
  // clang-format off
  static constexpr std::array<std::uint8_t, 14> packet{
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
  static constexpr std::array<std::uint8_t, 14> packet{
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
  static constexpr std::array<std::uint8_t, 10> packet{0x00, 0x11, 0x22, 0x33, 0x44,
                                                       0x55, 0xAA, 0xBB, 0xCC, 0xDD};

  CHECK_FALSE(parse_ethernet_header(std::span{packet}).has_value());
}
