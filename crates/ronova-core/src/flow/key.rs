use crate::{flow::Direction, packet::IpProtocol};

use super::Endpoint;

// Identifies one bidirectional communication flow
// Die Reihenfolge des Endpoints ist kanonisch, damit beide Paket Richtungen denselben FlowKey erzeugen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub endpoint_a: Endpoint,
    pub endpoint_b: Endpoint,
    pub protocol: IpProtocol,
}

impl FlowKey {
    // Creates a canonical FlowKey from two transport endpoints.
    // Die kleinere Endpoint-Represäntation wird immer zu endpoint_a
    pub fn new(first: Endpoint, second: Endpoint, protocol: IpProtocol) -> Self {
        if first <= second {
            Self {
                endpoint_a: first,
                endpoint_b: second,
                protocol,
            }
        } else {
            Self {
                endpoint_a: second,
                endpoint_b: first,
                protocol,
            }
        }
    }

    // Determines the direction of a packet relative to this canonical FlowKey.
    // Der FlowKey muss bereits zu den beiden Packet-Endpunkten passen.
    pub fn direction_of(&self, source: Endpoint, destination: Endpoint) -> Option<Direction> {
        match (source, destination) {
            (source, destination)
                if source == self.endpoint_a && destination == self.endpoint_b =>
            {
                Some(Direction::AtoB)
            }

            (source, destination)
                if source == self.endpoint_b && destination == self.endpoint_a =>
            {
                Some(Direction::BtoA)
            }

            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn endpoint(ip: [u8; 4], port: u16) -> Endpoint {
        Endpoint {
            ip: Ipv4Addr::from(ip),
            port,
        }
    }

    #[test]
    fn canonicalizes_endpoints_regardless_of_input_order() {
        let first = endpoint([10, 0, 0, 10], 443);
        let second = endpoint([10, 0, 0, 5], 49152);

        let key = FlowKey::new(first, second, IpProtocol::Tcp);

        assert_eq!(key.endpoint_a, second);
        assert_eq!(key.endpoint_b, first);
    }

    #[test]
    fn protocol_is_part_of_flow_identity() {
        let first = endpoint([10, 0, 0, 5], 49152);
        let second = endpoint([10, 0, 0, 10], 443);

        let tcp_key = FlowKey::new(first, second, IpProtocol::Tcp);
        let udp_key = FlowKey::new(first, second, IpProtocol::Udp);

        assert_ne!(tcp_key, udp_key);
    }

    #[test]
    fn determines_a_to_b_direction() {
        let endpoint_a = endpoint([10, 0, 0, 5], 49152);
        let endpoint_b = endpoint([10, 0, 0, 10], 443);

        let key = FlowKey::new(endpoint_a, endpoint_b, IpProtocol::Tcp);

        let direction = key.direction_of(endpoint_a, endpoint_b);

        assert_eq!(direction, Some(Direction::AtoB));
    }

    #[test]
    fn determines_b_to_a_direction() {
        let endpoint_a = endpoint([10, 0, 0, 5], 49152);
        let endpoint_b = endpoint([10, 0, 0, 10], 443);

        let key = FlowKey::new(endpoint_a, endpoint_b, IpProtocol::Tcp);

        let direction = key.direction_of(endpoint_b, endpoint_a);

        assert_eq!(direction, Some(Direction::BtoA));
    }

    #[test]
    fn rejects_endpoints_not_belonging_to_flow() {
        let first = endpoint([10, 0, 0, 10], 443);
        let second = endpoint([10, 0, 0, 5], 49152);
        let unrelated = endpoint([10, 0, 0, 20], 12345);

        let key = FlowKey::new(first, second, IpProtocol::Tcp);

        let direction = key.direction_of(unrelated, second);

        assert_eq!(direction, None);
    }
}
