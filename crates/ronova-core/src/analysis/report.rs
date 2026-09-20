use super::finding::Finding;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AnalysisReport {
    pub(super) findings: Vec<Finding>,
}

impl AnalysisReport {
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
}
