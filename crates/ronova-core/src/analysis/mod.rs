mod finding;
mod report;
mod state;

pub use finding::Finding;
pub use report::AnalysisReport;

#[cfg(test)]
mod tests {
    use super::Finding;
    use super::state::AnalysisState;
    use crate::capture::CaptureRecord;
    use crate::flow::{Direction, Endpoint, FlowKey};
    use crate::packet::{IpProtocol, PacketParser};

    #[test]
    fn convert_analysis_state_into_report() {
        let mut state = AnalysisState::new();

        state.push_finding(Finding);
        state.push_finding(Finding);

        let report = state.into_report();

        assert_eq!(report.findings().len(), 2);
        assert!(report.flows().is_empty());
    }

    #[test]
    fn tracks_flow_in_analysis_state() {
        let mut state = AnalysisState::new();

        let flow_key = FlowKey::new(
            Endpoint {
                ip: "10.0.0.1".parse().unwrap(),
                port: 50000,
            },
            Endpoint {
                ip: "10.0.0.2".parse().unwrap(),
                port: 443,
            },
            IpProtocol::Tcp,
        );

        state.update_flow(flow_key, Direction::AtoB, 100);
        state.update_flow(flow_key, Direction::BtoA, 200);

        let report = state.into_report();

        assert_eq!(report.flows().len(), 1);

        let flow = &report.flows()[0];

        assert_eq!(flow.packet_count(), 2);
        assert_eq!(flow.byte_count(), 300);
        assert_eq!(flow.a_to_b_packets(), 1);
        assert_eq!(flow.b_to_a_packets(), 1);
    }

    #[test]
    fn processes_tcp_packet_into_flow_state() {
        // A valid Ethernet + IPv4 + TCP packet:
        // 192.168.1.10:54321 -> 192.168.1.20:443
        // Ethernet = 14 bytes, IPv4 = 20 bytes, TCP = 20 bytes.
        let packet = [
            // Ethernet header.
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x66, 0x77, 0x88, 0x99, 0xaa, 0x08, 0x00,
            // IPv4 header.
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8,
            0x01, 0x0a, 0xc0, 0xa8, 0x01, 0x14, // TCP header.
            0xd4, 0x31, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00,
        ];

        // CaptureRecord only borrows the packet bytes.
        let record = CaptureRecord::new(&packet);

        // The parser is injected into AnalysisState instead of being owned by it.
        let parser = PacketParser::new();
        let mut state = AnalysisState::new();

        // The orchestration method should parse the packet and update the flow.
        state
            .process_packet(&parser, &record)
            .expect("valid TCP packet should be processed successfully");

        // Consuming AnalysisState produces the final report.
        let report = state.into_report();

        // Exactly one supported TCP flow should have been created.
        assert_eq!(report.flows().len(), 1);

        let flow = &report.flows()[0];

        // The complete captured frame contains 54 bytes.
        assert_eq!(flow.packet_count(), 1);
        assert_eq!(flow.byte_count(), 54);

        // The packet was observed in the A -> B direction.
        assert_eq!(flow.a_to_b_packets(), 1);
        assert_eq!(flow.b_to_a_packets(), 0);
        assert_eq!(flow.a_to_b_bytes(), 54);
        assert_eq!(flow.b_to_a_bytes(), 0);
    }
}
