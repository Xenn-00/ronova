use crate::flow::FlowReport;

use super::finding::Finding;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AnalysisReport {
    pub(super) findings: Vec<Finding>,
    pub(super) flows: Vec<FlowReport>,
}

impl AnalysisReport {
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn flows(&self) -> &[FlowReport] {
        &self.flows
    }
}
