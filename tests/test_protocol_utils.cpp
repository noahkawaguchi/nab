#include <catch2/catch_test_macros.hpp>

#include "packet_parser.hpp"
#include "protocol_types.hpp"

using namespace nab;

TEST_CASE("protocol_to_string converts protocols correctly", "[protocol]") {
  CHECK(protocol_to_string(Protocol::Tcp) == "TCP");
  CHECK(protocol_to_string(Protocol::Udp) == "UDP");
  CHECK(protocol_to_string(Protocol::Icmp) == "ICMP");
  CHECK(protocol_to_string(Protocol::Igmp) == "IGMP");
  CHECK(protocol_to_string(Protocol::Unknown) == "Unknown");
}

TEST_CASE("parse_protocol from string (case insensitive)", "[protocol]") {
  SECTION("Lowercase") {
    CHECK(parse_protocol("tcp") == Protocol::Tcp);
    CHECK(parse_protocol("udp") == Protocol::Udp);
    CHECK(parse_protocol("icmp") == Protocol::Icmp);
    CHECK(parse_protocol("igmp") == Protocol::Igmp);
  }

  SECTION("Uppercase") {
    CHECK(parse_protocol("TCP") == Protocol::Tcp);
    CHECK(parse_protocol("UDP") == Protocol::Udp);
    CHECK(parse_protocol("ICMP") == Protocol::Icmp);
    CHECK(parse_protocol("IGMP") == Protocol::Igmp);
  }

  SECTION("Mixed case") {
    CHECK(parse_protocol("TcP") == Protocol::Tcp);
    CHECK(parse_protocol("Udp") == Protocol::Udp);
    CHECK(parse_protocol("IcMp") == Protocol::Icmp);
  }

  SECTION("With whitespace") {
    CHECK(parse_protocol("  tcp  ") == Protocol::Tcp);
    CHECK(parse_protocol("\tudp\n") == Protocol::Udp);
    CHECK(parse_protocol(" ICMP ") == Protocol::Icmp);
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
  CHECK(get_service_name(9999).empty());
  CHECK(get_service_name(12345).empty());
  CHECK(get_service_name(1).empty());
}

TEST_CASE("ether_type_to_string converts EtherTypes correctly", "[ether_type]") {
  CHECK(ether_type_to_string(EtherType::Ipv4) == "IPv4");
  CHECK(ether_type_to_string(EtherType::Arp) == "ARP");
  CHECK(ether_type_to_string(EtherType::Ipv6) == "IPv6");
}
