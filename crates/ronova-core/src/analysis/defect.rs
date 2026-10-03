use serde::Serialize;

use crate::packet::PacketParseError;

// Describes one packet the could not be parsed as a valid supported packet.
#[derive(Debug, Serialize, Clone, Copy)]
pub struct PacketDefect {
    // Position of the defective packet in the capture stream.
    packet_number: u64,

    // Reason why ronova could not parse the packet.
    reason: PacketParseError,
}

impl PacketDefect {
    // Creates a new packet defect entry
    pub(crate) fn new(packet_number: u64, reason: PacketParseError) -> Self {
        Self {
            packet_number,
            reason,
        }
    }

    // Returns the packet number associated with this defect.
    pub fn packet_number(&self) -> u64 {
        self.packet_number
    }

    // Returns the parsing failure reason.
    pub fn reason(&self) -> &PacketParseError {
        &self.reason
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        analysis::AnalysisState,
        capture::{CaptureRecord, CaptureTimestamp},
        packet::{PacketParseError, PacketParser},
    };

    #[test]
    fn records_malformed_packet_as_defect() {
        let malformed_packet = [
            // Intentionally incomplete Ethernet header.
            // An Ethernet II header requires 14 bytes.
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ];

        // Packet number comes from the capture layer.
        let record = CaptureRecord::new(
            7,
            &malformed_packet,
            CaptureTimestamp::new(1, 1),
            malformed_packet.len() as u32,
        );

        let parser = PacketParser::new();
        let mut state = AnalysisState::new();

        // A malformed packet is a packet-level defect, not a fatal
        // analysis/capture failure.
        state
            .process_packet(&parser, &record)
            .expect("packet defect should be absorbed by AnalysisState");

        let report = state.into_report();

        assert_eq!(report.defects().len(), 1);
        assert!(report.flows().is_empty());

        let defect = &report.defects()[0];

        // The original capture position must be preserved.
        assert_eq!(defect.packet_number(), 7);

        // The parser should classify the incomplete Ethernet frame as truncated.
        assert!(matches!(defect.reason(), PacketParseError::Truncated));
    }

    #[test]
    fn continues_processing_after_packet_defect() {
        // A deliberately malformed packet.
        let malformed_packet = [
            // Incomplete Ethernet header.
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ];

        // A valid Ethernet + IPv4 + TCP packet.
        let valid_packet = [
            // Ethernet header.
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x66, 0x77, 0x88, 0x99, 0xaa, 0x08, 0x00,
            // IPv4 header.
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8,
            0x01, 0x0a, 0xc0, 0xa8, 0x01, 0x14, // TCP header.
            0xd4, 0x31, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00,
        ];

        let parser = PacketParser::new();
        let mut state = AnalysisState::new();

        // Packet #1 is valid.
        let record = CaptureRecord::new(
            1,
            &valid_packet,
            CaptureTimestamp::new(1, 1),
            valid_packet.len() as u32,
        );

        state
            .process_packet(&parser, &record)
            .expect("valid packet should be processed successfully");

        // Packet #2 is malformed.
        let record = CaptureRecord::new(
            2,
            &malformed_packet,
            CaptureTimestamp::new(1, 2),
            malformed_packet.len() as u32,
        );

        state
            .process_packet(&parser, &record)
            .expect("malformed packet should become a defect");

        // Packet #3 is valid again.
        let record = CaptureRecord::new(
            3,
            &valid_packet,
            CaptureTimestamp::new(1, 3),
            valid_packet.len() as u32,
        );

        state
            .process_packet(&parser, &record)
            .expect("processing should continue after a packet defect");

        let report = state.into_report();

        // Exactly one packet should be classified as defective.
        assert_eq!(report.defects().len(), 1);

        let defect = &report.defects()[0];

        // The defective packet must be packet #2.
        assert_eq!(defect.packet_number(), 2);

        // The valid packets before and after the defect must still
        // contribute to the same tracked flow.
        assert_eq!(report.flows().len(), 1);

        let flow = &report.flows()[0];

        assert_eq!(flow.packet_count(), 2);
        assert_eq!(flow.byte_count(), 108);
    }
}
