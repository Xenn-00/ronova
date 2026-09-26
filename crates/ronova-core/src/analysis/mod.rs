mod finding;
mod report;
mod state;

pub use finding::Finding;
pub use report::AnalysisReport;

#[cfg(test)]
mod tests {
    use super::Finding;
    use super::state::AnalysisState;
    use crate::flow::{Direction, Endpoint, FlowKey};
    use crate::packet::IpProtocol;

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
}
