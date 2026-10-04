use serde::Serialize;

use crate::flow::TcpObservation;

use super::{Direction, FlowTimestamp};

// Stores the accumulated statistics for one bidirectional flow.
// Der State gehört zu genau einem FlowKey und enthält nur owned data.
#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy)]
pub struct FlowState {
    // Total number of packets observed in this flow.
    pub packet_count: u64,

    // Total number of bytes observed in this flow.
    pub byte_count: u64,

    // Number of packets sent from endpoint_a to endpoint_b
    pub a_to_b_packets: u64,

    // Number of packets sent from endpoint_b to endpoint_a.
    pub b_to_a_packets: u64,

    // Number of bytes sent from endpoint_a to endpoint_b.
    pub a_to_b_bytes: u64,

    // Number of bytes sent from endpoint_b to endpoint_a.
    pub b_to_a_bytes: u64,

    // Timestamp of the first packet observed in this flow.
    pub first_seen: FlowTimestamp,

    // Timestamp of the most recent packet observed in this flow.
    pub last_seen: FlowTimestamp,

    // Direction observed for the first packet of this flow.
    pub first_direction: Direction,

    // Most recently observed TCP control flags for this flow.
    pub tcp_observation: Option<TcpObservation>,
}

impl FlowState {
    // Creates flow state from the first observed packet.
    //
    // Der erste Pakcet legt gleichzeitig first_seen und last_seen fest.
    pub fn new(
        direction: Direction,
        packet_length: usize,
        timestamp: FlowTimestamp,
        tcp_observation: Option<TcpObservation>,
    ) -> Self {
        let packet_length = packet_length as u64;

        let (a_to_b_packets, b_to_a_packets, a_to_b_bytes, b_to_a_bytes) = match direction {
            Direction::AtoB => (1, 0, packet_length, 0),
            Direction::BtoA => (0, 1, 0, packet_length),
        };

        Self {
            packet_count: 1,
            byte_count: packet_length,
            a_to_b_packets,
            b_to_a_packets,
            a_to_b_bytes,
            b_to_a_bytes,
            first_seen: timestamp,
            last_seen: timestamp,
            first_direction: direction,
            tcp_observation,
        }
    }

    // Updates the accumulated statistics with on observed packet.
    // Die Direction bestimmt, welche Richtungsspezifik-Statistik aktualisiert wird.
    pub fn update(
        &mut self,
        direction: Direction,
        packet_length: usize,
        timestamp: FlowTimestamp,
        tcp_observation: Option<TcpObservation>,
    ) {
        self.last_seen = timestamp;
        if tcp_observation.is_some() {
            self.tcp_observation = tcp_observation;
        }

        let packet_length = packet_length as u64;

        self.packet_count += 1;
        self.byte_count += packet_length;

        match direction {
            Direction::AtoB => {
                self.a_to_b_packets += 1;
                self.a_to_b_bytes += packet_length;
            }

            Direction::BtoA => {
                self.b_to_a_packets += 1;
                self.b_to_a_bytes += packet_length;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::flow::{FlowTimestamp, TcpObservation};

    use super::{Direction, FlowState};

    fn tcp_observation(syn: bool, ack: bool, fin: bool, rst: bool) -> TcpObservation {
        TcpObservation { syn, ack, fin, rst }
    }

    #[test]
    fn starts_empty() {
        let state = FlowState::new(Direction::AtoB, 0, FlowTimestamp::new(1, 1), None);

        assert_eq!(state.packet_count, 1);
        assert_eq!(state.byte_count, 0);
        assert_eq!(state.a_to_b_packets, 1);
        assert_eq!(state.b_to_a_packets, 0);
        assert_eq!(state.a_to_b_bytes, 0);
        assert_eq!(state.b_to_a_bytes, 0);
        assert_eq!(state.first_seen, FlowTimestamp::new(1, 1));
        assert_eq!(state.last_seen, FlowTimestamp::new(1, 1));
        assert_eq!(state.first_direction, Direction::AtoB);
    }

    #[test]
    fn updates_a_to_b_statistics() {
        let mut state = FlowState::new(Direction::AtoB, 0, FlowTimestamp::new(1, 1), None);

        state.update(Direction::AtoB, 100, FlowTimestamp::new(1, 2), None);

        assert_eq!(state.packet_count, 2);
        assert_eq!(state.byte_count, 100);
        assert_eq!(state.a_to_b_packets, 2);
        assert_eq!(state.a_to_b_bytes, 100);
        assert_eq!(state.b_to_a_packets, 0);
        assert_eq!(state.b_to_a_bytes, 0);
        assert_eq!(state.first_seen, FlowTimestamp::new(1, 1));
        assert_eq!(state.last_seen, FlowTimestamp::new(1, 2));
    }

    #[test]
    fn updates_b_to_a_statistics() {
        let mut state = FlowState::new(Direction::BtoA, 0, FlowTimestamp::new(1, 1), None);

        state.update(Direction::BtoA, 200, FlowTimestamp::new(1, 2), None);

        assert_eq!(state.packet_count, 2);
        assert_eq!(state.byte_count, 200);
        assert_eq!(state.a_to_b_packets, 0);
        assert_eq!(state.a_to_b_bytes, 0);
        assert_eq!(state.b_to_a_packets, 2);
        assert_eq!(state.b_to_a_bytes, 200);
        assert_eq!(state.first_seen, FlowTimestamp::new(1, 1));
        assert_eq!(state.last_seen, FlowTimestamp::new(1, 2));
        assert_eq!(state.first_direction, Direction::BtoA);
    }

    #[test]
    fn accumulates_both_directions() {
        let mut state = FlowState::new(Direction::AtoB, 0, FlowTimestamp::new(1, 1), None);

        state.update(Direction::AtoB, 100, FlowTimestamp::new(1, 2), None);
        state.update(Direction::AtoB, 150, FlowTimestamp::new(1, 3), None);
        state.update(Direction::BtoA, 80, FlowTimestamp::new(1, 4), None);

        assert_eq!(state.packet_count, 4);
        assert_eq!(state.byte_count, 330);

        assert_eq!(state.a_to_b_packets, 3);
        assert_eq!(state.a_to_b_bytes, 250);

        assert_eq!(state.b_to_a_packets, 1);
        assert_eq!(state.b_to_a_bytes, 80);
        assert_eq!(state.first_seen, FlowTimestamp::new(1, 1));
        assert_eq!(state.last_seen, FlowTimestamp::new(1, 4));

        assert_eq!(state.first_direction, Direction::AtoB);
    }

    #[test]
    fn stores_syn_observation() {
        let observation = tcp_observation(true, false, false, false);

        let state = FlowState::new(
            Direction::AtoB,
            60,
            FlowTimestamp::new(1, 1),
            Some(observation),
        );

        assert_eq!(state.tcp_observation, Some(observation))
    }

    #[test]
    fn stores_syn_ack_observation() {
        let observation = tcp_observation(true, true, false, false);

        let state = FlowState::new(
            Direction::BtoA,
            60,
            FlowTimestamp::new(1, 1),
            Some(observation),
        );

        assert_eq!(state.tcp_observation, Some(observation));
    }

    #[test]
    fn stores_rst_ack_observation() {
        let observation = tcp_observation(false, true, false, true);

        let state = FlowState::new(
            Direction::BtoA,
            54,
            FlowTimestamp::new(1, 3),
            Some(observation),
        );

        assert_eq!(state.tcp_observation, Some(observation));
    }

    #[test]
    fn keeps_tcp_observation_empty_for_non_tcp_flow() {
        let state = FlowState::new(Direction::AtoB, 80, FlowTimestamp::new(1, 4), None);

        assert_eq!(state.tcp_observation, None);
    }

    #[test]
    fn preserves_previous_tcp_observation_when_update_has_none() {
        let observation = tcp_observation(true, false, false, false);

        let mut state = FlowState::new(
            Direction::AtoB,
            60,
            FlowTimestamp::new(1, 1),
            Some(observation),
        );

        state.update(Direction::BtoA, 60, FlowTimestamp::new(1, 2), None);

        assert_eq!(state.tcp_observation, Some(observation));
    }
}
