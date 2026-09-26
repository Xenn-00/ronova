use super::{AnalysisReport, Finding};
use crate::{
    capture::CaptureRecord,
    flow::{Direction, FlowIdentity, FlowKey, FlowReport, FlowTracker},
    packet::{PacketParseError, PacketParser},
};

#[derive(Debug, Default)]
pub struct AnalysisState {
    findings: Vec<Finding>,
    flow_tracker: FlowTracker,
}

impl AnalysisState {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn into_report(self) -> AnalysisReport {
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

    // Parses one captured packet and updates flow state when the packet
    // contains a flow identity supported by Ronova.
    // Der AnalysisState koordiniert Parsing und Flow-Tracking,
    // ohne selbst die Packet-Parsing-Details zu übernehmen.
    pub fn process_packet(
        &mut self,
        parser: &PacketParser,
        record: &CaptureRecord<'_>,
    ) -> Result<(), PacketParseError> {
        let packet = parser.parse(record)?;

        if let Some(identity) = FlowIdentity::from_packet(&packet) {
            let (flow_key, direction) = identity.flow_key_and_direction();

            self.update_flow(flow_key, direction, record.data().len());
        }

        Ok(())
    }
}
