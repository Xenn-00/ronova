use std::time::Duration;

use serde::Serialize;

// Represents a timestamp used by the flow analysis layer.
//
// Der FlowTimestamp hält die Zeit unabhängig von der Capture-Schicht,
// damit die Flow-Logik nicht direckt von CaptureTimestamp abhängt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FlowTimestamp {
    seconds: u64,
    microseconds: u32,
}

impl FlowTimestamp {
    // Creates a flow timestamp from capture timestamp components.
    //
    // Die Umwandlung wird bewusst außerhalb der Capture-Schicht durchgeführt,
    // damit FlowTimestamp eine eigene Bedeutung innerhalb der Analyse behält.
    pub(crate) fn new(seconds: u64, microseconds: u32) -> Self {
        Self {
            seconds,
            microseconds,
        }
    }

    // Returns the timestamp in seconds.
    pub fn seconds(&self) -> u64 {
        self.seconds
    }

    // Returns the microseconds part of the timestamp.
    pub fn microseconds(&self) -> u32 {
        self.microseconds
    }

    // Returns the elapsed time from this timestamp to a later timestamp.
    //
    // Die Dauer wird nur zwischen zwei beobachteten Zeitpunkten berechnet.
    // Dadurch muss die Flow-Schicht keine Annahmen über fehlende Pakete machen.
    pub fn duration_since(&self, earlier: Self) -> Option<Duration> {
        if *self < earlier {
            return None;
        }

        let (seconds, microseconds) = if self.microseconds >= earlier.microseconds {
            (
                self.seconds - earlier.seconds,
                self.microseconds - earlier.microseconds,
            )
        } else {
            (
                self.seconds - earlier.seconds - 1,
                self.microseconds + 1_000_000 - earlier.microseconds,
            )
        };

        Some(Duration::new(seconds, microseconds * 1_000))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_duration_between_timestamps() {
        let earlier = FlowTimestamp::new(10, 250_000);
        let later = FlowTimestamp::new(13, 750_000);

        let duration = later
            .duration_since(earlier)
            .expect("later timestamp should not be earlier than the reference");

        assert_eq!(duration.as_secs(), 3);
        assert_eq!(duration.subsec_micros(), 500_000);
    }

    #[test]
    fn returns_none_when_timestamp_is_earlier() {
        let earlier = FlowTimestamp::new(13, 750_000);
        let later = FlowTimestamp::new(10, 250_000);

        assert_eq!(later.duration_since(earlier), None);
    }
}
