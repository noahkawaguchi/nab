#include <catch2/catch_test_macros.hpp>

#include "packet_parser.hpp"
#include "protocol_types.hpp"

using namespace nab;

TEST_CASE("protocol_to_string converts protocols correctly", "[protocol]") {
  CHECK(protocol_to_string(Protocol::TCP) == "TCP");
  CHECK(protocol_to_string(Protocol::UDP) == "UDP");
  CHECK(protocol_to_string(Protocol::ICMP) == "ICMP");
  CHECK(protocol_to_string(Protocol::IGMP) == "IGMP");
  CHECK(protocol_to_string(Protocol::Unknown) == "Unknown");
}

TEST_CASE("parse_protocol from string (case insensitive)", "[protocol]") {
  SECTION("Lowercase") {
    CHECK(parse_protocol("tcp") == Protocol::TCP);
    CHECK(parse_protocol("udp") == Protocol::UDP);
    CHECK(parse_protocol("icmp") == Protocol::ICMP);
    CHECK(parse_protocol("igmp") == Protocol::IGMP);
  }

  SECTION("Uppercase") {
    CHECK(parse_protocol("TCP") == Protocol::TCP);
    CHECK(parse_protocol("UDP") == Protocol::UDP);
    CHECK(parse_protocol("ICMP") == Protocol::ICMP);
    CHECK(parse_protocol("IGMP") == Protocol::IGMP);
  }

  SECTION("Mixed case") {
    CHECK(parse_protocol("TcP") == Protocol::TCP);
    CHECK(parse_protocol("Udp") == Protocol::UDP);
    CHECK(parse_protocol("IcMp") == Protocol::ICMP);
  }

  SECTION("With whitespace") {
    CHECK(parse_protocol("  tcp  ") == Protocol::TCP);
    CHECK(parse_protocol("\tudp\n") == Protocol::UDP);
    CHECK(parse_protocol(" ICMP ") == Protocol::ICMP);
  }

  SECTION("Invalid protocols") {
    CHECK(parse_protocol("invalid") == Protocol::Unknown);
    CHECK(parse_protocol("http") == Protocol::Unknown);
    CHECK(parse_protocol("") == Protocol::Unknown);
    CHECK(parse_protocol("   ") == Protocol::Unknown);
  }
}

TEST_CASE("get_service_name returns well-known port names", "[service]") {
  CHECK(get_service_name(22) == "/SSH");
  CHECK(get_service_name(53) == "/DNS");
  CHECK(get_service_name(80) == "/HTTP");
  CHECK(get_service_name(443) == "/HTTPS");
}

TEST_CASE("get_service_name returns empty for unknown ports", "[service]") {
  CHECK(get_service_name(9999) == "");
  CHECK(get_service_name(12345) == "");
  CHECK(get_service_name(1) == "");
}

TEST_CASE("ether_type_to_string converts EtherTypes correctly", "[ether_type]") {
  CHECK(ether_type_to_string(EtherType::IPv4) == "IPv4");
  CHECK(ether_type_to_string(EtherType::ARP) == "ARP");
  CHECK(ether_type_to_string(EtherType::IPv6) == "IPv6");
}
