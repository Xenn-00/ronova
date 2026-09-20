use super::{AnalysisReport, Finding};

#[derive(Debug, Default)]
pub(crate) struct AnalysisState {
    findings: Vec<Finding>,
}

impl AnalysisState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub(crate) fn into_report(self) -> AnalysisReport {
        AnalysisReport {
            findings: self.findings,
        }
    }
}
