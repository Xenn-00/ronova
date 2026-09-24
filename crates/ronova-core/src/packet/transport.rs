use crate::packet::ParsedUdp;

use super::ParsedTcp;

// Represents a recognized transport layer protocol.
// Der Grund für die Enum-Struktur ist, dass jedes Transportprotokoll
// seine eigenen semantischen Header-Daten besitzt.
#[derive(Debug, PartialEq, Eq)]
pub enum ParsedTransport {
    // Successfully parsed TCP segment.
    Tcp(ParsedTcp),

    // User Datagram Protocol.
    Udp(ParsedUdp),

    // Internet Control Message Protocol.
    Icmp {
        // ICMP type.
        icmp_type: u8,

        // ICMP code.
        icmp_code: u8,
    },

    // Internet Control Message Protocol version 6.
    Icmpv6 {
        // ICMPv6 type.
        icmp_type: u8,

        // ICMPv6 code.
        icmp_code: u8,
    },

    // The transport layer protocol is recognized but not yet supported by Ronova.
    Unsupported {
        // IANA protocol number.
        protocol: u8,
    },
}

#[cfg(test)]
mod tests {
    use super::ParsedTransport;
    use crate::packet::{ParsedTcp, ParsedUdp};

    #[test]
    fn represents_supported_transport_protocols() {
        // Ronova should distinguish the transport protocols it currently models.
        // Diese Varianten bilden zunächst nur die erkannte Protokollart ab.
        let tcp = ParsedTcp {
            source_port: 1234,
            destination_port: 5678,
            sequence_number: 1,
            acknowledgement_number: 2,
            ns: false,
            fin: false,
            syn: true,
            rst: false,
            psh: false,
            ack: true,
            urg: false,
            ece: false,
            cwr: false,
            window_size: 65535,
            checksum: 0x1234,
            urgent_pointer: 0,
        };

        assert_eq!(
            ParsedTransport::Tcp(tcp),
            ParsedTransport::Tcp(ParsedTcp {
                source_port: 1234,
                destination_port: 5678,
                sequence_number: 1,
                acknowledgement_number: 2,
                ns: false,
                fin: false,
                syn: true,
                rst: false,
                psh: false,
                ack: true,
                urg: false,
                ece: false,
                cwr: false,
                window_size: 65535,
                checksum: 0x1234,
                urgent_pointer: 0,
            })
        );

        assert_eq!(
            ParsedTransport::Udp(ParsedUdp {
                source_port: 1234,
                destination_port: 5678,
                length: 1000,
                checksum: 0x1234
            }),
            ParsedTransport::Udp(ParsedUdp {
                source_port: 1234,
                destination_port: 5678,
                length: 1000,
                checksum: 0x1234
            })
        );

        assert_eq!(
            ParsedTransport::Icmp {
                icmp_type: 8,
                icmp_code: 0,
            },
            ParsedTransport::Icmp {
                icmp_type: 8,
                icmp_code: 0,
            }
        );

        assert_eq!(
            ParsedTransport::Icmpv6 {
                icmp_type: 8,
                icmp_code: 0,
            },
            ParsedTransport::Icmpv6 {
                icmp_type: 8,
                icmp_code: 0,
            }
        );
    }

    #[test]
    fn preserves_unsupported_protocol_number() {
        // Unknown protocol numbers must remain observable.
        // Dies ist wichtig, um die Erkennung von Protokollen zu ermöglichen,
        // die Ronova noch nicht unterstützt.
        assert_eq!(
            ParsedTransport::Unsupported { protocol: 99 },
            ParsedTransport::Unsupported { protocol: 99 }
        );
    }
}
