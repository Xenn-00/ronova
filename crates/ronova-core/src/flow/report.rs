use serde::Serialize;

use crate::packet::IpProtocol;

use super::{Endpoint, FlowKey, FlowState};

// Represents the final reportable result of one observed flow.
// Der FlowReport beschreibt die Flow-Identität zusammen mit den
// während der Analyse gesammelten Statistiken.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct FlowReport {
    // First endpoint of the canonical flow.
    pub(super) endpoint_a: Endpoint,

    // Second endpoint of the canonical flow.
    pub(super) endpoint_b: Endpoint,

    // Transport protocol used by the flow.
    pub(super) protocol: IpProtocol,

    // Total number of packets observed in this flow.
    pub(super) packet_count: u64,

    // Total number of bytes observed in this flow.
    pub(super) byte_count: u64,

    // Number of packets sent from endpoint_a to endpoint_b.
    pub(super) a_to_b_packets: u64,

    // Number of packets sent from endpoint_b to endpoint_a.
    pub(super) b_to_a_packets: u64,

    // Number of bytes sent from endpoint_a to endpoint_b.
    pub(super) a_to_b_bytes: u64,

    // Number of bytes sent from endpoint_b to endpoint_a.
    pub(super) b_to_a_bytes: u64,
}

impl FlowReport {
    // Converts the internal flow key and mutable flow state into
    // an immutable report representation.
    // Die Runtime-Strukturen werden dabei vollständig konsumiert.
    pub(crate) fn from_parts(flow_key: FlowKey, flow_state: FlowState) -> Self {
        Self {
            endpoint_a: flow_key.endpoint_a,
            endpoint_b: flow_key.endpoint_b,
            protocol: flow_key.protocol,
            packet_count: flow_state.packet_count,
            byte_count: flow_state.byte_count,
            a_to_b_packets: flow_state.a_to_b_packets,
            b_to_a_packets: flow_state.b_to_a_packets,
            a_to_b_bytes: flow_state.a_to_b_bytes,
            b_to_a_bytes: flow_state.b_to_a_bytes,
        }
    }

    // Returns the first endpoint of the canonical flow.
    pub fn endpoint_a(&self) -> Endpoint {
        self.endpoint_a
    }

    // Returns the second endpoint of the canonical flow.
    pub fn endpoint_b(&self) -> Endpoint {
        self.endpoint_b
    }

    // Returns the transport protocol used by the flow.
    pub fn protocol(&self) -> IpProtocol {
        self.protocol
    }

    // Returns the total number of packets observed in the flow.
    pub fn packet_count(&self) -> u64 {
        self.packet_count
    }

    // Returns the total number of bytes observed in the flow.
    pub fn byte_count(&self) -> u64 {
        self.byte_count
    }

    // Returns the number of packets sent from endpoint_a to endpoint_b.
    pub fn a_to_b_packets(&self) -> u64 {
        self.a_to_b_packets
    }

    // Returns the number of packets sent from endpoint_b to endpoint_a.
    pub fn b_to_a_packets(&self) -> u64 {
        self.b_to_a_packets
    }

    // Returns the number of bytes sent from endpoint_a to endpoint_b.
    pub fn a_to_b_bytes(&self) -> u64 {
        self.a_to_b_bytes
    }

    // Returns the number of bytes sent from endpoint_b to endpoint_a.
    pub fn b_to_a_bytes(&self) -> u64 {
        self.b_to_a_bytes
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::{
        flow::{Direction, Endpoint, FlowKey, FlowState},
        packet::IpProtocol,
    };

    use super::FlowReport;

    #[test]
    fn converts_flow_key_and_state_into_report() {
        let flow_key = FlowKey::new(
            Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 1),
                port: 50000,
            },
            Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 2),
                port: 443,
            },
            IpProtocol::Tcp,
        );

        let mut flow_state = FlowState::default();

        flow_state.update(Direction::AtoB, 100);
        flow_state.update(Direction::BtoA, 200);

        let report = FlowReport::from_parts(flow_key, flow_state);

        assert_eq!(report.endpoint_a().ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(report.endpoint_a().port, 50000);

        assert_eq!(report.endpoint_b().ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(report.endpoint_b().port, 443);

        assert_eq!(report.protocol(), IpProtocol::Tcp);

        assert_eq!(report.packet_count(), 2);
        assert_eq!(report.byte_count(), 300);

        assert_eq!(report.a_to_b_packets(), 1);
        assert_eq!(report.a_to_b_bytes(), 100);

        assert_eq!(report.b_to_a_packets(), 1);
        assert_eq!(report.b_to_a_bytes(), 200);
    }
}
