#include <catch2/catch_test_macros.hpp>

#include "packet_filter.hpp"
#include "protocol_types.hpp"

using namespace nab;

TEST_CASE("PacketFilter matches protocol correctly", "[filter]") {
  static constexpr ParsedPacket tcp_packet{
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
  static constexpr ParsedPacket packet{
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
  static constexpr ParsedPacket packet{
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
  static constexpr ParsedPacket packet{
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
