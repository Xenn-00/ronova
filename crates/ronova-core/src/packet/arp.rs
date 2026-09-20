use etherparse::ArpPacketSlice;

use super::{error::PacketParseError, packet::ParsedArp};

/// Parses an Ethernet/IPv4 ARP packet into a Ronova-owned representation.
pub fn parse_arp(data: &[u8]) -> Result<ParsedArp, PacketParseError> {
    let arp = ArpPacketSlice::from_slice(data).map_err(|_| PacketParseError::Truncated)?;

    // Ronova v0.1 currently models ARP over Ethernet with IPv4 addresses.
    if arp.hw_addr_type().0 != 1
        || arp.proto_addr_type().0 != 0x0800
        || arp.hw_addr_size() != 6
        || arp.proto_addr_size() != 4
    {
        return Err(PacketParseError::Malformed);
    }

    let sender_hardware_address = arp
        .sender_hw_addr()
        .try_into()
        .map_err(|_| PacketParseError::Malformed)?;

    let sender_protocol_address = arp
        .sender_protocol_addr()
        .try_into()
        .map_err(|_| PacketParseError::Malformed)?;

    let target_hardware_address = arp
        .target_hw_addr()
        .try_into()
        .map_err(|_| PacketParseError::Malformed)?;

    let target_protocol_address = arp
        .target_protocol_addr()
        .try_into()
        .map_err(|_| PacketParseError::Malformed)?;

    Ok(ParsedArp {
        operation: arp.operation().0,
        sender_hardware_address,
        sender_protocol_address,
        target_hardware_address,
        target_protocol_address,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        capture::CaptureRecord,
        packet::{
            PacketParseError, PacketParser, ParsedArp, ParsedEthernet, ParsedNetwork, parse_arp,
        },
    };

    #[test]
    fn rejects_truncated_arp_packet() {
        let bytes = [
            // Deliberately shorter than a complete ARP packet.
            0x00, 0x01, 0x08, 0x00, 0x06,
        ];

        let result = parse_arp(&bytes);

        assert!(
            matches!(result, Err(PacketParseError::Truncated)),
            "an incomplete ARP packet should be classified as truncated"
        );
    }

    #[test]
    fn rejects_arp_with_unsupported_hardware_type() {
        let mut bytes = [
            0x00, 0x01, // Hardware type: Ethernet
            0x08, 0x00, // Protocol type: IPv4
            0x06, // Hardware address length
            0x04, // Protocol address length
            0x00, 0x01, // Operation: request
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Sender MAC
            192, 168, 1, 10, // Sender IPv4
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
            192, 168, 1, 1, // Target IPv4
        ];

        bytes[1] = 0x02;

        let result = parse_arp(&bytes);

        assert!(matches!(result, Err(PacketParseError::Malformed)));
    }

    #[test]
    fn rejects_arp_with_unsupported_protocol_type() {
        let mut bytes = [
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            192, 168, 1, 10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 192, 168, 1, 1,
        ];

        bytes[3] = 0x01;

        let result = parse_arp(&bytes);

        assert!(matches!(result, Err(PacketParseError::Malformed)));
    }

    #[test]
    fn dispatches_ethernet_arp_to_arp_parser() {
        let bytes = [
            // Ethernet destination MAC: 00:11:22:33:44:55
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Ethernet source MAC: 66:77:88:99:aa:bb
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // EtherType: ARP
            0x08, 0x06, // ARP hardware type: Ethernet
            0x00, 0x01, // ARP protocol type: IPv4
            0x08, 0x00, // Hardware address length
            0x06, // Protocol address length
            0x04, // Operation: request
            0x00, 0x01, // Sender MAC
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Sender IPv4: 192.168.1.10
            192, 168, 1, 10, // Target MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target IPv4: 192.168.1.1
            192, 168, 1, 1,
        ];

        let record = CaptureRecord::new(&bytes);
        let parser = PacketParser::new();

        let packet = parser
            .parse(&record)
            .expect("valid Ethernet/ARP packet should parse");

        assert_eq!(
            packet.ethernet,
            ParsedEthernet {
                source: [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
                destination: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                ether_type: 0x0806,
            }
        );

        assert_eq!(
            packet.network,
            ParsedNetwork::Arp(ParsedArp {
                operation: 1,
                sender_hardware_address: [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
                sender_protocol_address: [192, 168, 1, 10],
                target_hardware_address: [0, 0, 0, 0, 0, 0],
                target_protocol_address: [192, 168, 1, 1],
            })
        );
    }

    #[test]
    fn preserves_ethernet_arp_ethertype() {
        let bytes = [
            // destination MAC: 00:11:22:33:44:55
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Source MAC: 66:77:88:99:aa:bb
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // EtherType: ARP
            0x08, 0x06,
        ];

        let record = CaptureRecord::new(&bytes);
        let parser = PacketParser::new();

        let ethernet = parser
            .parse_ethernet(&record)
            .expect("valid Ethernet header should parse");

        assert_eq!(ethernet.destination, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(ethernet.source, [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        assert_eq!(ethernet.ether_type, 0x0806);
    }

    #[test]
    fn parses_ethernet_ipv4_arp_request() {
        let bytes = [
            0x00, 0x01, // Hardware type: Ethernet
            0x08, 0x00, // Protocol type: IPv4
            0x06, // Hardware address length
            0x04, // Protocol address length
            0x00, 0x01, // Operation: request
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Sender MAC: 66:77:88:99:aa::bb
            192, 168, 1, 10, // Sender IPv4: 192. 168.1.10
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC: 00:00:00:00:00:00
            192, 168, 1, 1, // Target IPv4: 192.168.1.1
        ];

        let arp = parse_arp(&bytes).expect("valid ARP packet should parse");

        assert_eq!(arp.operation, 1);

        assert_eq!(
            arp.sender_hardware_address,
            [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]
        );

        assert_eq!(arp.sender_protocol_address, [192, 168, 1, 10]);

        assert_eq!(arp.target_hardware_address, [0, 0, 0, 0, 0, 0]);

        assert_eq!(arp.target_protocol_address, [192, 168, 1, 1]);
    }
}
