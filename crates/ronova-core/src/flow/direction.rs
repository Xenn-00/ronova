// Represents the direction of a packet relative to a canonical FlowKey.
// Direction does not belong to the flow itself; it describes one packet's movement between the two endpoints of an existing flow.
#[derive(Debug, PartialEq, Eq)]
pub enum Direction {
    // Packet moves from endpoint_a to endpoint_b.
    AtoB,
    // Packet moves from endpoint_b to endpoint_a.
    BtoA,
}
