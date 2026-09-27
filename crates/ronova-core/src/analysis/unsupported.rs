use serde::Serialize;

// Explains why a successfully parsed packet is not curerntly supported.
#[derive(Debug, Serialize, Clone, Copy)]
pub enum UnsupportedReason {
    // The Ethernet frame uses an EtherType ronova does not currently model.
    EtherType(u16),

    // The IPv4 packet uses an IP protocol Ronova does not currently model.
    IpProtocol(u8),
}

/// Describes one valid packet that Ronova currently cannot analyse further.
#[derive(Debug, Serialize, Clone, Copy)]
pub struct UnsupportedPacket {
    // Position of the packet in the capture stream.
    packet_number: u64,

    // Protocol-level reason why the packet is unsupported.
    reason: UnsupportedReason,
}

impl UnsupportedPacket {
    /// Creates a new unsupported packet entry.
    pub(crate) fn new(packet_number: u64, reason: UnsupportedReason) -> Self {
        Self {
            packet_number,
            reason,
        }
    }

    /// Returns the packet number associated with this entry.
    pub fn packet_number(&self) -> u64 {
        self.packet_number
    }

    /// Returns the reason why the packet is unsupported.
    pub fn reason(&self) -> &UnsupportedReason {
        &self.reason
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::{AnalysisState, UnsupportedReason},
        capture::CaptureRecord,
        packet::PacketParser,
    };

    #[test]
    fn records_unsupported_ether_type_separately_from_defects() {
        let packet = [
            // Ethernet destination MAC.
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Ethernet source MAC.
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Valid but unsupported EtherType.
            0x12, 0x34,
        ];

        let record = CaptureRecord::new(23, &packet);

        let parser = PacketParser::new();
        let mut state = AnalysisState::new();

        state
            .process_packet(&parser, &record)
            .expect("unsupported protocol should not be a packet defect");

        let report = state.into_report();

        assert!(report.defects().is_empty());
        assert_eq!(report.unsupported_packets().len(), 1);
        assert!(report.flows().is_empty());

        let unsupported = &report.unsupported_packets()[0];

        assert_eq!(unsupported.packet_number(), 23);

        assert!(matches!(
            unsupported.reason(),
            UnsupportedReason::EtherType(0x1234)
        ));
    }

    #[test]
    fn records_unsupported_ip_protocol_separately_from_defects() {
        let packet = [
            // Ethernet destination MAC.
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Ethernet source MAC.
            0x00, 0x66, 0x77, 0x88, 0x99, 0xaa, // EtherType: IPv4.
            0x08, 0x00, // IPv4 header.
            0x45, 0x00, // Total IPv4 length = 20 bytes.
            0x00, 0x14, // Identification.
            0x00, 0x01, // Flags + fragment offset.
            0x00, 0x00, // TTL.
            0x40, // Unsupported IP protocol.
            0x84, // Header checksum.
            0x00, 0x00, // Source: 192.168.1.10.
            0xc0, 0xa8, 0x01, 0x0a, // Destination: 192.168.1.20.
            0xc0, 0xa8, 0x01, 0x14,
        ];

        let record = CaptureRecord::new(31, &packet);

        let parser = PacketParser::new();
        let mut state = AnalysisState::new();

        state
            .process_packet(&parser, &record)
            .expect("unsupported IP protocol should not be a packet defect");

        let report = state.into_report();

        assert!(report.defects().is_empty());
        assert_eq!(report.unsupported_packets().len(), 1);
        assert!(report.flows().is_empty());

        let unsupported = &report.unsupported_packets()[0];

        assert_eq!(unsupported.packet_number(), 31);

        assert!(matches!(
            unsupported.reason(),
            UnsupportedReason::IpProtocol(0x84)
        ));
    }
}
