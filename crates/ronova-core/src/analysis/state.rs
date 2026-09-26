use super::{AnalysisReport, Finding};
use crate::flow::{Direction, FlowKey, FlowReport, FlowTracker};

#[derive(Debug, Default)]
pub(crate) struct AnalysisState {
    findings: Vec<Finding>,
    flow_tracker: FlowTracker,
}

impl AnalysisState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub(crate) fn into_report(self) -> AnalysisReport {
        // Consume the tracker so no FlowState or FlowKey needs to be cloned.
        // Der Tracker wird vollständig konsumiert und in finale Reports umgewandelt.
        let flows: Vec<FlowReport> = self
            .flow_tracker
            .into_iter()
            .map(|(flow_key, flow_state)| FlowReport::from_parts(flow_key, flow_state))
            .collect();

        AnalysisReport {
            findings: self.findings,
            flows,
        }
    }

    // Updates the tracked state of one observed flow.
    // Der AnalysisState leitet die Flow-Daten nur an den FlowTracker weiter.
    pub(crate) fn update_flow(
        &mut self,
        flow_key: FlowKey,
        direction: Direction,
        packet_length: usize,
    ) {
        self.flow_tracker.update(flow_key, direction, packet_length);
    }
}
