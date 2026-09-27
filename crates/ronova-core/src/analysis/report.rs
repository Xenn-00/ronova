use crate::{
    analysis::{PacketDefect, UnsupportedPacket},
    flow::FlowReport,
};

use super::finding::Finding;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AnalysisReport {
    pub(super) findings: Vec<Finding>,
    pub(super) flows: Vec<FlowReport>,
    pub(super) unsupported_packets: Vec<UnsupportedPacket>,
    pub(super) defects: Vec<PacketDefect>,
}

impl AnalysisReport {
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn flows(&self) -> &[FlowReport] {
        &self.flows
    }

    // Returns all packet-level parsing defects recorded during analysis.
    pub fn defects(&self) -> &[PacketDefect] {
        &self.defects
    }

    // Returns all valid but unsupported packets recorded during analysis.
    pub fn unsupported_packets(&self) -> &[UnsupportedPacket] {
        &self.unsupported_packets
    }
}
