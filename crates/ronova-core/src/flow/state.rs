use super::Direction;

// Stores the accumulated statistics for one bidirectional flow.
// Der State gehört zu genau einem FlowKey und enthält nur owned data.
#[derive(Debug, Default, PartialEq, Eq)]
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
}

impl FlowState {
    // Updates the accumulated statistics with on observed packet.
    // Die Direction bestimmt, welche Richtungsspezifik-Statistik aktualisiert wird.
    pub fn update(&mut self, direction: Direction, packet_length: usize) {
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
    use super::{Direction, FlowState};

    #[test]
    fn starts_empty() {
        let state = FlowState::default();

        assert_eq!(state.packet_count, 0);
        assert_eq!(state.byte_count, 0);
        assert_eq!(state.a_to_b_packets, 0);
        assert_eq!(state.b_to_a_packets, 0);
        assert_eq!(state.a_to_b_bytes, 0);
        assert_eq!(state.b_to_a_bytes, 0);
    }

    #[test]
    fn updates_a_to_b_statistics() {
        let mut state = FlowState::default();

        state.update(Direction::AtoB, 100);

        assert_eq!(state.packet_count, 1);
        assert_eq!(state.byte_count, 100);
        assert_eq!(state.a_to_b_packets, 1);
        assert_eq!(state.a_to_b_bytes, 100);
        assert_eq!(state.b_to_a_packets, 0);
        assert_eq!(state.b_to_a_bytes, 0);
    }

    #[test]
    fn updates_b_to_a_statistics() {
        let mut state = FlowState::default();

        state.update(Direction::BtoA, 200);

        assert_eq!(state.packet_count, 1);
        assert_eq!(state.byte_count, 200);
        assert_eq!(state.a_to_b_packets, 0);
        assert_eq!(state.a_to_b_bytes, 0);
        assert_eq!(state.b_to_a_packets, 1);
        assert_eq!(state.b_to_a_bytes, 200);
    }

    #[test]
    fn accumulates_both_directions() {
        let mut state = FlowState::default();

        state.update(Direction::AtoB, 100);
        state.update(Direction::AtoB, 150);
        state.update(Direction::BtoA, 80);

        assert_eq!(state.packet_count, 3);
        assert_eq!(state.byte_count, 330);

        assert_eq!(state.a_to_b_packets, 2);
        assert_eq!(state.a_to_b_bytes, 250);

        assert_eq!(state.b_to_a_packets, 1);
        assert_eq!(state.b_to_a_bytes, 80);
    }
}
