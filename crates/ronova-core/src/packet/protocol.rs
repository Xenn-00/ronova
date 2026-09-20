// Identifies the protocol carried by an IP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    // Internet Control Message Protocol (ICMP)
    Icmp,

    // Transmission Control Protocol (TCP)
    Tcp,

    // User Datagram Protocol (UDP)
    Udp,

    // Internet Control Message Protocol for IPv6 (ICMPv6)
    Icmpv6,

    // Protocol not currently interpreted by ronova.
    Other(u8),
}
