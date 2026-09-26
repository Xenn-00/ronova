use std::collections::{HashMap, hash_map::IntoIter};

use super::{Direction, FlowKey, FlowState};

// Tracks the accumulated state of all observed bidirectional flows.
// Der Tracker verwaltet nur FlowKey -> FlowState und kennt keine Packet-Parsing-Details.
#[derive(Debug, Default)]
pub struct FlowTracker {
    flows: HashMap<FlowKey, FlowState>,
}

impl FlowTracker {
    // Creates an empty flow tracker
    pub fn new() -> Self {
        Self::default()
    }

    // updates the state of one flow with an observed packet.
    // Ein neuer Flow wird beim ersten beobachteten Packet automatisch angelegt.
    pub fn update(&mut self, flow_key: FlowKey, direction: Direction, packet_length: usize) {
        let state = self.flows.entry(flow_key).or_default();

        state.update(direction, packet_length);
    }

    // Returns the current state of a flow without taking owership of it.
    pub fn get(&self, flow_key: &FlowKey) -> Option<&FlowState> {
        self.flows.get(flow_key)
    }

    // Returns the number of currently tracked flows.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    // Returns whether the tracker currently contains no flows.
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

impl IntoIterator for FlowTracker {
    type Item = (FlowKey, FlowState);
    type IntoIter = IntoIter<FlowKey, FlowState>;

    // Consumes the tracker and yields every tracked flow together
    // with its accumulated state.
    // Der Tracker wird vollständig konsumiert; dadurch sind keine
    // Clones der Flow-Daten für den finalen Report notwendig.
    fn into_iter(self) -> Self::IntoIter {
        self.flows.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::{
        flow::{Direction, Endpoint, FlowKey},
        packet::IpProtocol,
    };

    use super::FlowTracker;

    fn tcp_flow_key() -> FlowKey {
        FlowKey::new(
            Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 1),
                port: 50000,
            },
            Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 2),
                port: 443,
            },
            IpProtocol::Tcp,
        )
    }

    #[test]
    fn starts_empty() {
        let tracker = FlowTracker::new();

        assert!(tracker.is_empty());
        assert_eq!(tracker.len(), 0);
    }

    #[test]
    fn creates_flow_on_first_packet() {
        let mut tracker = FlowTracker::new();
        let flow_key = tcp_flow_key();

        tracker.update(flow_key, Direction::AtoB, 100);

        assert_eq!(tracker.len(), 1);

        let state = tracker
            .get(&flow_key)
            .expect("flow should exist after first packet");

        assert_eq!(state.packet_count, 1);
        assert_eq!(state.byte_count, 100);
        assert_eq!(state.a_to_b_packets, 1);
        assert_eq!(state.a_to_b_bytes, 100);
    }

    #[test]
    fn updates_existing_flow_in_both_directions() {
        let mut tracker = FlowTracker::new();
        let flow_key = tcp_flow_key();

        tracker.update(flow_key, Direction::AtoB, 100);
        tracker.update(flow_key, Direction::BtoA, 200);
        tracker.update(flow_key, Direction::AtoB, 50);

        assert_eq!(tracker.len(), 1);

        let state = tracker
            .get(&flow_key)
            .expect("flow should exist after updates");

        assert_eq!(state.packet_count, 3);
        assert_eq!(state.byte_count, 350);

        assert_eq!(state.a_to_b_packets, 2);
        assert_eq!(state.a_to_b_bytes, 150);

        assert_eq!(state.b_to_a_packets, 1);
        assert_eq!(state.b_to_a_bytes, 200);
    }

    #[test]
    fn keeps_different_protocols_as_separate_flows() {
        let mut tracker = FlowTracker::new();

        let tcp_key = tcp_flow_key();

        let udp_key = FlowKey::new(tcp_key.endpoint_a, tcp_key.endpoint_b, IpProtocol::Udp);

        tracker.update(tcp_key, Direction::AtoB, 100);
        tracker.update(udp_key, Direction::AtoB, 200);

        assert_eq!(tracker.len(), 2);

        assert_eq!(
            tracker
                .get(&tcp_key)
                .expect("TCP flow should exist")
                .byte_count,
            100
        );

        assert_eq!(
            tracker
                .get(&udp_key)
                .expect("UDP flow should exist")
                .byte_count,
            200
        );
    }

    #[test]
    fn consumes_tracker_into_flow_entries() {
        let mut tracker = FlowTracker::new();
        let flow_key = tcp_flow_key();

        tracker.update(flow_key, Direction::AtoB, 100);

        let entries: Vec<_> = tracker.into_iter().collect();

        assert_eq!(entries.len(), 1);

        let (reported_key, state) = entries
            .into_iter()
            .next()
            .expect("tracker should contain one flow");

        assert_eq!(reported_key, flow_key);
        assert_eq!(state.packet_count, 1);
        assert_eq!(state.byte_count, 100);
    }
}
