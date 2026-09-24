// Represents a successfully parsed UDP datagram.
// ronova benötigt nur die semantichen werte, die für die erste flow und udp state analyse benötigt werden.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedUdp {
    // Identifies the sending application or service
    pub source_port: u16,

    // Identifies the receiving application or service
    pub destination_port: u16,

    // Total length of the UDP datagram, including header and payload.
    pub length: u16,

    // UDP checksum as captured in the packet.
    pub checksum: u16,
}
