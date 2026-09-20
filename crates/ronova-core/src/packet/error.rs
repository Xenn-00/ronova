// Errors produces while parsing an individual captured packet.
#[derive(Debug)]
pub enum PacketParseError {
    // The captured bytes do not contain a complete packet header.
    Truncated,
    // The packet contains bytes that cannot be interpreted as a valid
    // Ethernet/network packet by the parser.
    Malformed,

    // The packet uses a link/network/transport protocol that ronova
    // does not currently model.
    Unsupported,
}
