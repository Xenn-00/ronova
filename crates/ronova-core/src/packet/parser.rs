use etherparse::{
    Ethernet2Slice, Ipv4Slice, TcpSlice, UdpSlice,
    err::{LenError, ipv4::SliceError, tcp::HeaderSliceError},
};
use std::net::Ipv4Addr;

use crate::{
    capture::CaptureRecord,
    packet::{
        IpProtocol, ParsedIpv4, ParsedNetwork, ParsedTcp, ParsedTransport, ParsedUdp, parse_arp,
    },
};

use super::{
    error::PacketParseError,
    packet::{ParsedEthernet, ParsedPacket},
};

// Parses capture packet bytes into Ronova-owned packet representations.
pub struct PacketParser;

impl PacketParser {
    // Creates a packet parser.
    pub const fn new() -> Self {
        Self
    }

    // Parses the Ethernet layer of a captured packet.
    pub fn parse_ethernet(
        &self,
        record: &CaptureRecord<'_>,
    ) -> Result<ParsedEthernet, PacketParseError> {
        let ethernet = self.parse_ethernet_slice(record)?;

        Ok(ParsedEthernet {
            source: ethernet.source(),
            destination: ethernet.destination(),
            ether_type: ethernet.ether_type().0,
        })
    }

    // Parses a TCP segment from an IPv4 payload.
    // der parser übernimmt bewusst nur die Header-Interpretation
    // die nutzdaten bleiben als borrowed Slice im ursprünglichen Capture.
    pub fn parse_tcp(&self, payload: &[u8]) -> Result<ParsedTcp, PacketParseError> {
        let tcp = TcpSlice::from_slice(payload).map_err(Self::map_tcp_error)?;

        Ok(ParsedTcp {
            source_port: tcp.source_port(),
            destination_port: tcp.destination_port(),
            sequence_number: tcp.sequence_number(),
            acknowledgement_number: tcp.acknowledgment_number(),
            ns: tcp.ns(),
            fin: tcp.fin(),
            syn: tcp.syn(),
            rst: tcp.rst(),
            psh: tcp.psh(),
            ack: tcp.ack(),
            urg: tcp.urg(),
            ece: tcp.ece(),
            cwr: tcp.cwr(),
            window_size: tcp.window_size(),
            checksum: tcp.checksum(),
            urgent_pointer: tcp.urgent_pointer(),
        })
    }

    pub fn parse_udp(&self, payload: &[u8]) -> Result<ParsedUdp, PacketParseError> {
        // Parse the captured bytes as a UDP header without copying the payload. return error if didn't match
        let udp = UdpSlice::from_slice(payload).map_err(Self::map_error)?;
        Ok(ParsedUdp {
            source_port: udp.source_port(),
            destination_port: udp.destination_port(),
            length: udp.length(),
            checksum: udp.checksum(),
        })
    }

    // Parses an IPv4 packet payload into Ronova's normalized representation.
    pub fn parse_ipv4(&self, payload: &[u8]) -> Result<ParsedIpv4, PacketParseError> {
        let ipv4 = Ipv4Slice::from_slice(payload).map_err(Self::map_ipv4_error)?;

        Ok(Self::parsed_ipv4_from_slice(&ipv4))
    }

    // Parses an Ethernet frame and dispatches its payload according
    // to the Ethernet EtherType
    pub fn parse(&self, record: &CaptureRecord<'_>) -> Result<ParsedPacket, PacketParseError> {
        let ethernet_slice = self.parse_ethernet_slice(record)?;

        let ethernet = ParsedEthernet {
            source: ethernet_slice.source(),
            destination: ethernet_slice.destination(),
            ether_type: ethernet_slice.ether_type().0,
        };

        let network = match ethernet.ether_type {
            0x0806 => {
                let arp = parse_arp(ethernet_slice.payload_slice())?;
                ParsedNetwork::Arp(arp)
            }

            0x0800 => {
                let ipv4_slice = Ipv4Slice::from_slice(ethernet_slice.payload_slice())
                    .map_err(Self::map_ipv4_error)?;

                let ipv4 = Self::parsed_ipv4_from_slice(&ipv4_slice);
                let transport = self.parse_ipv4_transport(&ipv4_slice)?;

                ParsedNetwork::Ipv4 {
                    packet: ipv4,
                    transport,
                }
            }

            ether_type => ParsedNetwork::Unsupported { ether_type },
        };

        Ok(ParsedPacket { ethernet, network })
    }

    // Parses the Ethernet frame without discarding the borrowed
    // etherparse representation needed by downstream dispatch.
    fn parse_ethernet_slice<'a>(
        &self,
        record: &'a CaptureRecord<'a>,
    ) -> Result<Ethernet2Slice<'a>, PacketParseError> {
        Ethernet2Slice::from_slice_without_fcs(record.data()).map_err(Self::map_error)
    }

    // Converts an already validated IPv4 slice into ronova IPv4 representation.
    fn parsed_ipv4_from_slice(ipv4: &Ipv4Slice<'_>) -> ParsedIpv4 {
        let header = ipv4.header();

        ParsedIpv4 {
            source: Ipv4Addr::from(header.source()),
            destination: Ipv4Addr::from(header.destination()),
            protocol: Self::map_ip_protocol(header.protocol().0),
            ttl: header.ttl(),
            total_length: header.total_len(),
            identification: header.identification(),
            dont_fragment: header.dont_fragment(),
            more_fragments: header.more_fragments(),
            fragment_offset: header.fragments_offset().value(),
        }
    }

    // Parses the IPv4 transport payload according to the IPv4 protocol field.
    // Die Trennung verhindert, dass ein erkannter IP-Protokolltyp mit einem
    // erfolgreich geparsten Transport-Header verwechselt wird.
    fn parse_ipv4_transport(
        &self,
        ipv4: &Ipv4Slice<'_>,
    ) -> Result<ParsedTransport, PacketParseError> {
        match ipv4.header().protocol().0 {
            6 => Ok(ParsedTransport::Tcp(
                self.parse_tcp(ipv4.payload().payload)?,
            )),
            17 => Ok(ParsedTransport::Udp(
                self.parse_udp(ipv4.payload().payload)?,
            )),
            protocol => Ok(ParsedTransport::Unsupported { protocol }),
        }
    }

    // Converts an IANA IP protocol number into Ronova's semantic protocol type.
    fn map_ip_protocol(protocol: u8) -> IpProtocol {
        match protocol {
            1 => IpProtocol::Icmp,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            58 => IpProtocol::Icmpv6,
            other => IpProtocol::Other(other),
        }
    }

    // Converts IPv4 slice errors into Ronova's packet parsing taxonomy.
    fn map_ipv4_error(error: SliceError) -> PacketParseError {
        match error {
            SliceError::Len(_) => PacketParseError::Truncated,
            SliceError::Header(_) => PacketParseError::Malformed,
            SliceError::Exts(_) => PacketParseError::Malformed,
        }
    }

    // Converts TCP parsing errors into Ronova's packet parsing taxonomy.
    fn map_tcp_error(error: HeaderSliceError) -> PacketParseError {
        match error {
            // The TCP header contains invalid or inconsistent values.
            HeaderSliceError::Content(_) => PacketParseError::Malformed,
            // The captured bytes are not long enough to contain the TCP header.
            HeaderSliceError::Len(_) => PacketParseError::Truncated,
        }
    }

    // Converts etherparse errors into Ronova's packet parsing taxonomy.
    fn map_error(_error: LenError) -> PacketParseError {
        PacketParseError::Truncated
    }
}

#[cfg(test)]
mod tests {

    use std::net::Ipv4Addr;

    use crate::{
        capture::CaptureRecord,
        packet::{IpProtocol, PacketParseError, PacketParser, ParsedNetwork, ParsedTransport},
    };

    #[test]
    fn dispatches_unknown_ether_type_as_unsupported() {
        let bytes = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Ethernet destination MAC.
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Ethernet source MAC.
            0x12, 0x34, // Unknown EtherType.
        ];

        let record = CaptureRecord::new(&bytes);
        let parser = PacketParser::new();

        let packet = parser
            .parse(&record)
            .expect("valid Ethernet frame with unknown EtherType should parse");

        assert_eq!(packet.ethernet.ether_type, 0x1234);

        assert_eq!(
            packet.network,
            ParsedNetwork::Unsupported { ether_type: 0x1234 }
        );
    }

    #[test]
    fn preserves_ethernet_ipv6_ethertype() {
        let bytes = [
            // destination MAC: 00:11:22:33:44:55
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Source MAC: 66:77:88:99:aa:bb
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // EtherType: IPv6
            0x86, 0xDD,
        ];

        let record = CaptureRecord::new(&bytes);
        let parser = PacketParser::new();

        let ethernet = parser
            .parse_ethernet(&record)
            .expect("valid Ethernet header should parse");

        assert_eq!(ethernet.destination, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(ethernet.source, [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        assert_eq!(ethernet.ether_type, 0x86DD);
    }

    #[test]
    fn rejects_truncated_ethernet_header() {
        let bytes = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

        let record = CaptureRecord::new(&bytes);
        let parser = PacketParser::new();

        let result = parser.parse_ethernet(&record);

        assert!(
            matches!(result, Err(PacketParseError::Truncated)),
            "an incomplete Ethernet header should be classified as truncated"
        )
    }

    #[test]
    fn preserves_unsupported_ether_type() {
        let bytes = [
            // Destination MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Source MAC
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Unsupported EtherType
            0x12, 0x34,
        ];

        let record = CaptureRecord::new(&bytes);
        let parser = PacketParser::new();

        let packet = parser
            .parse(&record)
            .expect("valid Ethernet frame should parse");

        assert_eq!(
            packet.network,
            ParsedNetwork::Unsupported { ether_type: 0x1234 }
        );
    }

    #[test]
    fn dispatches_ipv4_tcp_payload_to_tcp_parser() {
        let bytes = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Destination MAC.
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Source MAC.
            0x08, 0x00, // EtherType: IPv4.
            0x45, // IPv4 header: version 4, IHL 5.
            0x00, // DSCP/ECN.
            0x00, 0x28, // Total length: 40 bytes (20 IPv4 + 20 TCP).
            0x12, 0x34, // Identification.
            0x40, 0x00, // Don't Fragment flag.
            0x40, // TTL.
            0x06, // Protocol: TCP.
            0x00, 0x00, // Header checksum.
            0xc0, 0xa8, 0x01, 0x0a, // Source: 192.168.1.10.
            0xc0, 0xa8, 0x01, 0x14, // Destination: 192.168.1.20.
            0xd4, 0x31, // TCP source port: 54321.
            0x01, 0xbb, // TCP destination port: 443.
            0x00, 0x00, 0x03, 0xe8, // Sequence number: 1000.
            0x00, 0x00, 0x07, 0xd0, // Acknowledgement number: 2000.
            0x50, // Data offset: 5 (20-byte header).
            0x12, // SYN + ACK.
            0xfa, 0xf0, // Window size.
            0x12, 0x34, // Checksum.
            0x00, 0x00, // Urgent pointer.
        ];

        let record = CaptureRecord::new(&bytes);
        let parser = PacketParser::new();

        let packet = parser
            .parse(&record)
            .expect("valid IPv4/TCP packet should parse");

        match packet.network {
            ParsedNetwork::Ipv4 {
                packet: ipv4,
                transport: ParsedTransport::Tcp(tcp),
            } => {
                assert_eq!(ipv4.source, Ipv4Addr::new(192, 168, 1, 10));
                assert_eq!(ipv4.destination, Ipv4Addr::new(192, 168, 1, 20));
                assert_eq!(ipv4.protocol, IpProtocol::Tcp);

                assert_eq!(tcp.source_port, 54321);
                assert_eq!(tcp.destination_port, 443);
                assert_eq!(tcp.sequence_number, 1000);
                assert_eq!(tcp.acknowledgement_number, 2000);
                assert!(tcp.syn);
                assert!(tcp.ack);
            }

            other => panic!("expected parsed IPv4/TCP packet, got {other:?}"),
        }
    }

    #[test]
    fn parses_tcp_header() {
        let payload = [
            0xd4, 0x31, // source port: 54321
            0x01, 0xbb, // destination port: 443.
            0x00, 0x00, 0x03, 0xe8, // sequence number: 1000
            0x00, 0x00, 0x07, 0xd0, // acknowledgement number: 2000
            0x50, // data offset: 5 (20-byte header), NS disabled
            0x12, // flags: SYN + ACK
            0xfa, 0xf0, // window size: 64240
            0x12, 0x34, // checksum: 0x1234
            0x00, 0x00, // urgent pointer: 0
        ];

        let parser = PacketParser::new();

        let tcp = parser
            .parse_tcp(&payload)
            .expect("valid TCP header should parse");

        assert_eq!(tcp.source_port, 54321);
        assert_eq!(tcp.destination_port, 443);
        assert_eq!(tcp.sequence_number, 1000);
        assert_eq!(tcp.acknowledgement_number, 2000);

        assert!(!tcp.ns);
        assert!(!tcp.fin);
        assert!(!tcp.rst);
        assert!(!tcp.psh);
        assert!(tcp.syn);
        assert!(tcp.ack);
        assert!(!tcp.urg);
        assert!(!tcp.ece);
        assert!(!tcp.cwr);

        assert_eq!(tcp.window_size, 64240);
        assert_eq!(tcp.checksum, 0x1234);
        assert_eq!(tcp.urgent_pointer, 0);
    }

    #[test]
    fn parses_udp_header() {
        let parser = PacketParser::new();

        // Minimal valid UDP datagram:
        // 8 byte header + 4 byte payload
        let payload = [
            0x04, 0xd2, // source port: 1234
            0x00, 0x35, // destination_port: 53
            0x00, 0x0c, // length: 12 bytes
            0x12, 0x34, // checksum
            0xde, 0xad, 0xbe, 0xef, // payload
        ];

        let udp = parser
            .parse_udp(&payload)
            .expect("valid UDP datagram should parse");

        assert_eq!(udp.source_port, 1234);
        assert_eq!(udp.destination_port, 53);
        assert_eq!(udp.length, 12);
        assert_eq!(udp.checksum, 0x1234);
    }

    #[test]
    fn rejects_truncated_udp_header() {
        let parser = PacketParser::new();

        // UDP headers require 8 bytes.
        let payload = [0x04, 0xD2, 0x00, 0x35, 0x00, 0x08];

        let result = parser.parse_udp(&payload);

        assert!(matches!(result, Err(PacketParseError::Truncated)));
    }

    #[test]
    fn parses_ipv4_udp_packet() {
        let parser = PacketParser::new();

        // Ethernet II header (14 bytes) + ipv4 header (20 bytes)
        // + UDP header (8 bytes) + 4 byte payload.
        let bytes = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // MAC destination
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // MAC source
            0x08, 0x00, // EtherType: ipv4
            // IP header
            0x45, // version 4, IHL 5
            0x00, // DSCP/ECN
            0x00, 0x20, // total length: 32 bytes
            0x12, 0x34, // identification
            0x00, 0x00, // flags + fragment offset
            0x40, // ttl
            0x11, // protocol: UDP (17)
            0x00, 0x00, // header checksum
            0xc0, 0xa8, 0x01, 0x0a, // source: 192.168.1.10
            0xc0, 0xa8, 0x01, 0x14, // source: 192.168.1.20
            // UDP header
            0x04, 0xd2, // source port: 1234
            0x00, 0x35, // destionation port: 53
            0x00, 0x0c, // udp length: 12 bytes
            0x12, 0x34, // udp checksum
            // udp payload
            0xde, 0xad, 0xbe, 0xef,
        ];

        // Constructing CaptureRecord
        let record = CaptureRecord::new(&bytes);

        let packet = parser
            .parse(&record)
            .expect("valid IPv4/UDP packet should parse");

        match packet.network {
            ParsedNetwork::Ipv4 {
                packet: ipv4,
                transport: ParsedTransport::Udp(udp),
            } => {
                assert_eq!(ipv4.protocol, IpProtocol::Udp);

                assert_eq!(udp.source_port, 1234);
                assert_eq!(udp.destination_port, 53);
                assert_eq!(udp.length, 12);
                assert_eq!(udp.checksum, 0x1234);
            }

            other => panic!("expected IPv4/UDP packet, got {other:?}"),
        }
    }
}
