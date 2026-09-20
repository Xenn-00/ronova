// Represents a recognized transport layer protocol.
// Der Grund für eine Darstellung ist, dass ein erkannter
// IP Protokolltyp noch nicht bedeutet, dass das Paket korrekt geparst werden kann.
#[derive(Debug, PartialEq, Eq)]
pub enum ParsedTransport {
    // Transmission Controll Protocol
    Tcp {
        // Source port number.
        source_port: u16,

        // Destination port number.
        destination_port: u16,
    },

    // User Datagram Protocol
    Udp {
        // Source port number.
        source_port: u16,

        // Destination port number.
        destination_port: u16,
    },

    // Internet Control Message Protocol
    Icmp {
        // ICMP type.
        icmp_type: u8,

        // ICMP code.
        icmp_code: u8,
    },

    // Internet Control Message Protocol version 6
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

    #[test]
    fn represents_supported_transport_protocols() {
        // Ronova should distinguish the transport protocols it currently models.
        // Diese Varianten bilden zunächst nur die erkannten Protokollart ab
        // die eigentlichen Header werden erst in den nächsten Schritten geparst.
        assert_eq!(
            ParsedTransport::Tcp {
                source_port: 1234,
                destination_port: 5678
            },
            ParsedTransport::Tcp {
                source_port: 1234,
                destination_port: 5678
            }
        );
        assert_eq!(
            ParsedTransport::Udp {
                source_port: 1234,
                destination_port: 1234
            },
            ParsedTransport::Udp {
                source_port: 1234,
                destination_port: 1234
            }
        );
        assert_eq!(
            ParsedTransport::Icmp {
                icmp_type: 8,
                icmp_code: 0
            },
            ParsedTransport::Icmp {
                icmp_type: 8,
                icmp_code: 0
            }
        );
        assert_eq!(
            ParsedTransport::Icmpv6 {
                icmp_type: 8,
                icmp_code: 0
            },
            ParsedTransport::Icmpv6 {
                icmp_type: 8,
                icmp_code: 0
            }
        )
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
