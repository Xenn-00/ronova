// Represents a successfully parsed TCP segment.
// wir übernehmen nur die semantischen werte, die ronova für die
// erste flow und tcp state analyse benötigt.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedTcp {
    // tcp source port.
    pub source_port: u16,

    // tcp destination port.
    pub destination_port: u16,

    // tcp sequence number.
    pub sequence_number: u32,

    // tcp acknowledgement number.
    pub acknowledgement_number: u32,

    // ECN-nonce flag. -> nonce ist ein Zahl, die nur einziges Mal verwendet wird, um zu signalisieren, dass der Sender ECN unterstützt.
    // ECN: Explicit Congestion Notification, ein Mechanismus, der es Routern ermöglicht, Netzwerküberlastungen zu signalisieren, ohne Pakete zu verwerfen.
    pub ns: bool,

    // FIN-flag.
    pub fin: bool,

    // SYN-flag.
    pub syn: bool,

    // RST flag.
    pub rst: bool,

    // PSH flag.
    pub psh: bool,

    // ACK flag.
    pub ack: bool,

    // URG flag.
    pub urg: bool,

    // ECN-Echo flag.
    pub ece: bool,

    // Congestion Window Reduced flag.
    pub cwr: bool,

    // TCP receive window size.
    pub window_size: u16,

    // TCP checksum.
    pub checksum: u16,

    // TCP urgent pointer.
    pub urgent_pointer: u16,
}
