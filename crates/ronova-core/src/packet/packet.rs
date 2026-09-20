use crate::packet::{ParsedIpv4, ParsedTransport};

// Ronova's representation of a successfully parsed Ethernet frame.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedEthernet {
    // Source MAC address.
    pub source: [u8; 6],

    // Destination MAC address.
    pub destination: [u8; 6],

    // Ethernet EtherType.
    pub ether_type: u16,
}

// Ronova's representation of an ARP packet.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedArp {
    // ARP operation code.
    pub operation: u16,

    // Hardware address of the sender.
    pub sender_hardware_address: [u8; 6],

    // Protocol address of the sender.
    pub sender_protocol_address: [u8; 4],

    // Hardware address of the target.
    pub target_hardware_address: [u8; 6],

    // Protocol address of the target.
    pub target_protocol_address: [u8; 4],
}

// Represents a network-layer packet recognized by Ronova.
#[derive(Debug, PartialEq, Eq)]
pub enum ParsedNetwork {
    // Address Resolution Protocol packet.
    Arp(ParsedArp),

    // Internet Protocol version 4 packet with its parsed transport payload.
    Ipv4 {
        // Parsed IPv4 header.
        packet: ParsedIpv4,

        // Parsed transport-layer payload.
        transport: ParsedTransport,
    },

    // EtherType is currently unsupported by Ronova.
    Unsupported {
        ether_type: u16,
    },
}

// Represents a successfully parsed packet at the layers currently
// understood by Ronova.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedPacket {
    // Parsed Ethernet frame.
    pub ethernet: ParsedEthernet,

    // Parsed network-layer payload.
    pub network: ParsedNetwork,
}
