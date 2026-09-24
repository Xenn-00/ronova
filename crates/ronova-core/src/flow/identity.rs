use crate::{
    flow::{Direction, FlowKey},
    packet::{IpProtocol, ParsedNetwork, ParsedPacket, ParsedTransport},
};

use super::Endpoint;

// Represents the flow-relevant information extracted from one parsed packet.
// Die ursprüngliche Paket-Richtung bleibt erhalten, bevor der FlowKey
// die beiden Endpoints kanonisiert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowIdentity {
    // Endpoint that sent the packet.
    pub source: Endpoint,

    // Endpoint that receives the packet.
    pub destination: Endpoint,

    // Transport protocol carried by the IPv4 packet.
    pub protocol: IpProtocol,
}

impl FlowIdentity {
    // Extracts flow-relevant information from a parsed packet.
    // Nur IPv4 with a currently supported transport protocol
    // can produce a FlowIdentity.
    pub fn from_packet(packet: &ParsedPacket) -> Option<Self> {
        let ParsedNetwork::Ipv4 {
            packet: ipv4,
            transport,
        } = &packet.network
        else {
            return None;
        };

        let (source_port, destination_port) = match transport {
            ParsedTransport::Tcp(tcp) => (tcp.source_port, tcp.destination_port),
            ParsedTransport::Udp(udp) => (udp.source_port, udp.destination_port),
            ParsedTransport::Icmp { .. }
            | ParsedTransport::Icmpv6 { .. }
            | ParsedTransport::Unsupported { .. } => return None,
        };

        Some(Self {
            source: Endpoint {
                ip: ipv4.source,
                port: source_port,
            },
            destination: Endpoint {
                ip: ipv4.destination,
                port: destination_port,
            },
            protocol: ipv4.protocol,
        })
    }

    // Creates the canonical FlowKey and determines the packet direction.
    // Der FlowKey identifiziert den bidirektionalen Flow,
    // während Direction die Richtung dieses konkreten Packets beschreibt.
    pub fn flow_key_and_direction(&self) -> (FlowKey, Direction) {
        let flow_key = FlowKey::new(self.source, self.destination, self.protocol);

        let direction = flow_key
            .direction_of(self.source, self.destination)
            .expect("FlowIdentity endpoints must belong to its FlowKey");

        (flow_key, direction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{
        ParsedArp, ParsedEthernet, ParsedIpv4, ParsedNetwork, ParsedTcp, ParsedTransport, ParsedUdp,
    };
    use std::net::Ipv4Addr;

    fn ethernet() -> ParsedEthernet {
        ParsedEthernet {
            source: [0, 1, 2, 3, 4, 5],
            destination: [6, 7, 8, 9, 10, 11],
            ether_type: 0x0800,
        }
    }

    #[test]
    fn extracts_tcp_flow_identity() {
        let packet = ParsedPacket {
            ethernet: ethernet(),
            network: ParsedNetwork::Ipv4 {
                packet: ParsedIpv4 {
                    source: Ipv4Addr::new(10, 0, 0, 5),
                    destination: Ipv4Addr::new(10, 0, 0, 10),
                    protocol: IpProtocol::Tcp,
                    ttl: 64,
                    total_length: 40,
                    identification: 1,
                    dont_fragment: true,
                    more_fragments: false,
                    fragment_offset: 0,
                },
                transport: ParsedTransport::Tcp(ParsedTcp {
                    source_port: 49152,
                    destination_port: 443,
                    sequence_number: 1,
                    acknowledgement_number: 0,
                    ns: false,
                    fin: false,
                    syn: true,
                    rst: false,
                    psh: false,
                    ack: false,
                    urg: false,
                    ece: false,
                    cwr: false,
                    window_size: 65535,
                    checksum: 0,
                    urgent_pointer: 0,
                }),
            },
        };

        let identity =
            FlowIdentity::from_packet(&packet).expect("TCP packet should produce a flow identity");

        assert_eq!(
            identity.source,
            Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 5),
                port: 49152,
            }
        );

        assert_eq!(
            identity.destination,
            Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 10),
                port: 443,
            }
        );

        assert_eq!(identity.protocol, IpProtocol::Tcp);
    }

    #[test]
    fn extracts_udp_flow_identity() {
        let packet = ParsedPacket {
            ethernet: ethernet(),
            network: ParsedNetwork::Ipv4 {
                packet: ParsedIpv4 {
                    source: Ipv4Addr::new(10, 0, 0, 5),
                    destination: Ipv4Addr::new(10, 0, 0, 10),
                    protocol: IpProtocol::Udp,
                    ttl: 64,
                    total_length: 40,
                    identification: 1,
                    dont_fragment: true,
                    more_fragments: false,
                    fragment_offset: 0,
                },
                transport: ParsedTransport::Udp(ParsedUdp {
                    source_port: 49153,
                    destination_port: 53,
                    length: 12,
                    checksum: 0x1234,
                }),
            },
        };

        let identity =
            FlowIdentity::from_packet(&packet).expect("UDP packet should produce a flow identity");

        assert_eq!(
            identity.source,
            Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 5),
                port: 49153,
            }
        );
        assert_eq!(
            identity.destination,
            Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 10),
                port: 53,
            }
        );
        assert_eq!(identity.protocol, IpProtocol::Udp);
    }

    #[test]
    fn arp_does_not_produce_flow_identity() {
        let packet = ParsedPacket {
            ethernet: ethernet(),
            network: ParsedNetwork::Arp(ParsedArp {
                operation: 1,
                sender_hardware_address: [0, 1, 2, 3, 4, 5],
                sender_protocol_address: [10, 0, 0, 5],
                target_hardware_address: [0, 0, 0, 0, 0, 0],
                target_protocol_address: [10, 0, 0, 1],
            }),
        };

        let identity = FlowIdentity::from_packet(&packet);

        assert_eq!(identity, None);
    }

    // An IPv4 packet with an unsupported transport protocol
    // cannot produce a flow identity.
    #[test]
    fn unsupported_transport_does_not_produce_flow_identity() {
        let packet = ParsedPacket {
            ethernet: ethernet(),
            network: ParsedNetwork::Ipv4 {
                packet: ParsedIpv4 {
                    source: Ipv4Addr::new(10, 0, 0, 5),
                    destination: Ipv4Addr::new(10, 0, 0, 10),
                    // GRE (protocol 47) is currently not modeled by Ronova.
                    protocol: IpProtocol::Other(47),
                    ttl: 64,
                    total_length: 40,
                    identification: 1,
                    dont_fragment: true,
                    more_fragments: false,
                    fragment_offset: 0,
                },
                transport: ParsedTransport::Unsupported { protocol: 47 },
            },
        };

        let identity = FlowIdentity::from_packet(&packet);

        assert_eq!(identity, None);
    }

    #[test]
    fn creates_flow_key_and_direction_from_tcp_identity() {
        let identity = FlowIdentity {
            source: Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 5),
                port: 49152,
            },
            destination: Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 10),
                port: 443,
            },
            protocol: IpProtocol::Tcp,
        };

        let (flow_key, direction) = identity.flow_key_and_direction();

        assert_eq!(flow_key.endpoint_a, identity.source);

        assert_eq!(flow_key.endpoint_b, identity.destination);

        assert_eq!(flow_key.protocol, IpProtocol::Tcp);

        assert_eq!(direction, Direction::AtoB);
    }

    #[test]
    fn creates_same_flow_key_for_reverse_tcp_identity() {
        let forward = FlowIdentity {
            source: Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 5),
                port: 49152,
            },
            destination: Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 10),
                port: 443,
            },
            protocol: IpProtocol::Tcp,
        };

        let reverse = FlowIdentity {
            source: Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 10),
                port: 443,
            },
            destination: Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 5),
                port: 49152,
            },
            protocol: IpProtocol::Tcp,
        };

        let (forward_key, forward_direction) = forward.flow_key_and_direction();

        let (reverse_key, reverse_direction) = reverse.flow_key_and_direction();

        // Both packet directions must resolve to the same bidirectional flow.
        assert_eq!(forward_key, reverse_key);

        assert_eq!(forward_direction, Direction::AtoB);
        assert_eq!(reverse_direction, Direction::BtoA);
    }
}
