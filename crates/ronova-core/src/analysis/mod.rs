mod finding;
mod report;
mod state;

pub use finding::Finding;
pub use report::AnalysisReport;

#[cfg(test)]
mod tests {
    use super::Finding;
    use super::state::AnalysisState;

    #[test]
    fn convert_analysis_state_into_report() {
        let mut state = AnalysisState::new();

        state.push_finding(Finding);
        state.push_finding(Finding);

        let report = state.into_report();

        assert_eq!(report.findings().len(), 2);
    }
}
