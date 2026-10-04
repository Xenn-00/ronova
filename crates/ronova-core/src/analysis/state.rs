use super::{AnalysisReport, Finding, PacketDefect, UnsupportedPacket, UnsupportedReason};
use crate::{
    capture::CaptureRecord,
    flow::{
        Direction, FlowIdentity, FlowKey, FlowReport, FlowTimestamp, FlowTracker, TcpObservation,
    },
    packet::{PacketParseError, PacketParser, ParsedNetwork, ParsedTransport},
};

#[derive(Debug, Default)]
pub struct AnalysisState {
    findings: Vec<Finding>,
    flow_tracker: FlowTracker,
    unsupported_packets: Vec<UnsupportedPacket>,
    defects: Vec<PacketDefect>,
}

impl AnalysisState {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    // Records a packet-level parsing defect without retaining the packet bytes.
    pub(crate) fn push_defect(&mut self, packet_number: u64, reason: PacketParseError) {
        self.defects.push(PacketDefect::new(packet_number, reason));
    }

    // Records a valid packet that Ronova cannot currently analyse further.
    pub(crate) fn push_unsupported(&mut self, packet_number: u64, reason: UnsupportedReason) {
        self.unsupported_packets
            .push(UnsupportedPacket::new(packet_number, reason));
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
            defects: self.defects,
            unsupported_packets: self.unsupported_packets,
        }
    }

    // Updates the tracked state of one observed flow.
    // Der AnalysisState leitet die Flow-Daten nur an den FlowTracker weiter.
    pub(crate) fn update_flow(
        &mut self,
        flow_key: FlowKey,
        direction: Direction,
        packet_length: usize,
        timestamp: FlowTimestamp,
        tcp_observation: Option<TcpObservation>,
    ) {
        self.flow_tracker.update(
            flow_key,
            direction,
            packet_length,
            timestamp,
            tcp_observation,
        );
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
        let packet = match parser.parse(record) {
            Ok(packet) => packet,

            Err(reason) => {
                // Store only packet metadata instead of retaining the raw bytes.
                self.push_defect(record.packet_number(), reason);

                // Packet-level defects are recoverable, so processing continue.
                return Ok(());
            }
        };

        // Record valid but unsupported packets separately from defective packets.
        match &packet.network {
            ParsedNetwork::Unsupported { ether_type } => {
                self.push_unsupported(
                    record.packet_number(),
                    UnsupportedReason::EtherType(*ether_type),
                );

                return Ok(());
            }

            ParsedNetwork::Ipv4 {
                transport: ParsedTransport::Unsupported { protocol },
                ..
            } => {
                self.push_unsupported(
                    record.packet_number(),
                    UnsupportedReason::IpProtocol(*protocol),
                );

                return Ok(());
            }

            _ => {}
        }

        // Converts capture-layer timestamp metadata into flow-layer timestamp metadata.
        //
        // Die Flow-Schicht soll nicht direkt von CaptureTimestamp abhängen,
        // deswegen wird die Zeit an der Grenze zwischen Analysis und Flow umgewandelt.
        let capture_timestamp = record.timestamp();
        let timestamp = FlowTimestamp::new(
            capture_timestamp.seconds(),
            capture_timestamp.microseconds(),
        );

        // Only supported packets reach flow tracking.
        if let Some(identity) = FlowIdentity::from_packet(&packet) {
            let (flow_key, direction) = identity.flow_key_and_direction();

            let tcp_observation = match &packet.network {
                ParsedNetwork::Ipv4 {
                    transport: ParsedTransport::Tcp(tcp),
                    ..
                } => Some(TcpObservation::from_tcp(tcp)),

                _ => None,
            };

            self.update_flow(
                flow_key,
                direction,
                record.captured_length(),
                timestamp,
                tcp_observation,
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::{AnalysisState, Finding, PacketDefect, UnsupportedPacket, UnsupportedReason},
        capture::{CaptureRecord, CaptureTimestamp},
        flow::{Direction, Endpoint, FlowKey, FlowTimestamp},
        packet::{IpProtocol, PacketParseError, PacketParser},
    };

    #[test]
    fn converts_analysis_state_into_report() {
        let mut state = AnalysisState::new();

        // Findings should be moved into the final report.
        state.push_finding(Finding);
        state.push_finding(Finding);

        let defect = PacketDefect::new(10, PacketParseError::Truncated);

        let unsupported = UnsupportedPacket::new(20, UnsupportedReason::EtherType(0x1234));

        // Defects should also be moved without being lost.
        state.push_defect(defect.packet_number(), *defect.reason());

        // Unsupported packets should also survive the state -> report
        // ownership transition.
        state.push_unsupported(unsupported.packet_number(), *unsupported.reason());

        let report = state.into_report();

        assert_eq!(report.findings().len(), 2);
        assert_eq!(report.defects().len(), 1);
        assert_eq!(report.unsupported_packets().len(), 1);
        assert!(report.flows().is_empty());
    }

    #[test]
    fn tracks_flow_in_analysis_state() {
        let mut state = AnalysisState::new();

        let flow_key = FlowKey::new(
            Endpoint {
                ip: "10.0.0.1".parse().unwrap(),
                port: 50000,
            },
            Endpoint {
                ip: "10.0.0.2".parse().unwrap(),
                port: 443,
            },
            IpProtocol::Tcp,
        );

        state.update_flow(
            flow_key,
            Direction::AtoB,
            100,
            FlowTimestamp::new(1, 1),
            None,
        );
        state.update_flow(
            flow_key,
            Direction::BtoA,
            200,
            FlowTimestamp::new(1, 2),
            None,
        );

        let report = state.into_report();

        assert_eq!(report.flows().len(), 1);

        let flow = &report.flows()[0];

        assert_eq!(flow.packet_count(), 2);
        assert_eq!(flow.byte_count(), 300);
        assert_eq!(flow.a_to_b_packets(), 1);
        assert_eq!(flow.b_to_a_packets(), 1);
    }

    #[test]
    fn processes_tcp_packet_into_flow_state() {
        // A valid Ethernet + IPv4 + TCP packet:
        // 192.168.1.10:54321 -> 192.168.1.20:443
        // Ethernet = 14 bytes, IPv4 = 20 bytes, TCP = 20 bytes.
        let packet = [
            // Ethernet header.
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x66, 0x77, 0x88, 0x99, 0xaa, 0x08, 0x00,
            // IPv4 header.
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8,
            0x01, 0x0a, 0xc0, 0xa8, 0x01, 0x14, // TCP header.
            0xd4, 0x31, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00,
        ];

        // CaptureRecord only borrows the packet bytes.
        let record =
            CaptureRecord::new(1, &packet, CaptureTimestamp::new(1, 2), packet.len() as u32);

        // The parser is injected into AnalysisState instead of being owned by it.
        let parser = PacketParser::new();
        let mut state = AnalysisState::new();

        // The orchestration method should parse the packet and update the flow.
        state
            .process_packet(&parser, &record)
            .expect("valid TCP packet should be processed successfully");

        // Consuming AnalysisState produces the final report.
        let report = state.into_report();

        // Exactly one supported TCP flow should have been created.
        assert_eq!(report.flows().len(), 1);

        let flow = &report.flows()[0];

        // The complete captured frame contains 54 bytes.
        assert_eq!(flow.packet_count(), 1);
        assert_eq!(flow.byte_count(), 54);

        // The packet was observed in the A -> B direction.
        assert_eq!(flow.a_to_b_packets(), 1);
        assert_eq!(flow.b_to_a_packets(), 0);
        assert_eq!(flow.a_to_b_bytes(), 54);
        assert_eq!(flow.b_to_a_bytes(), 0);
    }
}
