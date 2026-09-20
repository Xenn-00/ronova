use std::net::Ipv4Addr;

use super::protocol::IpProtocol;

// Ronova's normalized representation of an IPv4 packet.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedIpv4 {
    // Source IPv4 address.
    pub source: Ipv4Addr,

    // Destination IPv4 address.
    pub destination: Ipv4Addr,

    // Protocol carried by the IPv4 packet.
    pub protocol: IpProtocol,

    // Time to Live value
    pub ttl: u8,

    /// Total IPv4 packet length, including the header.
    pub total_length: u16,

    /// IPv4 identification field.
    pub identification: u16,

    /// Indicates that the packet must not be fragmented.
    pub dont_fragment: bool,

    /// Indicates that additional fragments follow.
    pub more_fragments: bool,

    /// Fragment offset of this packet.
    pub fragment_offset: u16,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::{
        capture::CaptureRecord,
        packet::{IpProtocol, PacketParseError, PacketParser, ParsedNetwork},
    };

    #[test]
    fn parses_ethernet_header() {
        let bytes = [
            // destination MAC: 00:11:22:33:44:55
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Source MAC: 66:77:88:99:aa:bb
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // EtherType: IPv4
            0x08, 0x00,
        ];

        let record = CaptureRecord::new(&bytes);
        let parser = PacketParser::new();

        let ethernet = parser
            .parse_ethernet(&record)
            .expect("valid Ethernet header should parse");

        assert_eq!(ethernet.destination, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(ethernet.source, [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        assert_eq!(ethernet.ether_type, 0x0800);
    }

    #[test]
    fn rejects_truncated_ipv4_packet() {
        let bytes = [0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06];

        let parser = PacketParser::new();

        let result = parser.parse_ipv4(&bytes);

        assert!(
            matches!(result, Err(PacketParseError::Truncated)),
            "truncated IPv4 input should return PacketParseError::Truncated"
        );
    }

    #[test]
    fn rejects_malformed_ipv4_packet() {
        let bytes = [
            // Invalid IP version: 6 instead of 4, IHL = 5.
            0x65, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 10,
            192, 168, 1, 20,
        ];

        let parser = PacketParser::new();

        let result = parser.parse_ipv4(&bytes);

        assert!(
            matches!(result, Err(PacketParseError::Malformed)),
            "malformed IPv4 input should return PacketParseError::Malformed"
        );
    }

    #[test]
    fn dispatches_ipv4_ether_type_to_ipv4_parser() {
        let bytes = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Ethernet destination MAC.
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Ethernet source MAC.
            0x08, 0x00, // EtherType: IPv4.
            0x45, // IPv4 header: version 4, IHL 5.
            0x00, // DSCP/ECN.
            0x00, 0x28, // Total length: 40 bytes (20 IPv4 + 20 TCP).
            0x12, 0x34, // Identification.
            0x40, 0x00, // Don't Fragment flag.
            0x40, // TTL.
            0x06, // Protocol: TCP.
            0x00, 0x00, // Header checksum.
            192, 168, 1, 10, // Source IP: 192.168.1.10.
            192, 168, 1, 20, // Destination IP: 192.168.1.20.
            0xd4, 0x31, // Source port: 54321.
            0x01, 0xbb, // Destination port: 443.
            0x00, 0x00, 0x00, 0x01, // Sequence number.
            0x00, 0x00, 0x00, 0x00, // Acknowledgement number.
            0x50, // Data offset: 5 (20-byte TCP header).
            0x02, // SYN flag.
            0xff, 0xff, // Window size.
            0x00, 0x00, // Checksum.
            0x00, 0x00, // Urgent pointer.
        ];

        let record = CaptureRecord::new(&bytes);
        let parser = PacketParser::new();

        let packet = parser
            .parse(&record)
            .expect("valid Ethernet/IPv4 packet should parse");

        assert_eq!(packet.ethernet.ether_type, 0x0800);

        match packet.network {
            ParsedNetwork::Ipv4 {
                packet: ipv4,
                transport: _,
            } => {
                assert_eq!(ipv4.source, Ipv4Addr::new(192, 168, 1, 10));
                assert_eq!(ipv4.destination, Ipv4Addr::new(192, 168, 1, 20));
                assert_eq!(ipv4.protocol, IpProtocol::Tcp);
            }

            other => panic!("expected ParsedNetwork::Ipv4, got {other:?}"),
        }
    }

    #[test]
    fn parses_ipv4_header_into_ronova_representation() {
        let bytes = [
            0x45, // Version 4, IHL 5.
            0x00, // DSCP/ECN.
            0x00, 0x14, // Total length: 20 bytes.
            0x12, 0x34, // Identification: 0x1234.
            0x40, 0x00, // Flags + fragment offset: Don't Fragment.
            0x40, // TTL: 64.
            0x06, // Protocol: TCP.
            0x00, 0x00, // Header checksum.
            192, 168, 1, 10, // Source: 192.168.1.10.
            192, 168, 1, 20, // Destination: 192.168.1.20.
        ];

        let parser = PacketParser::new();

        let ipv4 = parser
            .parse_ipv4(&bytes)
            .expect("valid IPv4 header should parse");

        assert_eq!(ipv4.source, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(ipv4.destination, Ipv4Addr::new(192, 168, 1, 20));
        assert_eq!(ipv4.protocol, IpProtocol::Tcp);
        assert_eq!(ipv4.ttl, 64);
        assert_eq!(ipv4.total_length, 20);
        assert_eq!(ipv4.identification, 0x1234);
        assert!(ipv4.dont_fragment);
        assert!(!ipv4.more_fragments);
        assert_eq!(ipv4.fragment_offset, 0);
    }
}
