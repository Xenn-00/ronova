#[derive(Debug)]
pub struct CaptureRecord<'a> {
    // Sequential number assigned by the capture reader.
    packet_number: u64,

    // Borrowed packet bytes owned by the capture parser buffer.
    data: &'a [u8],
}

impl<'a> CaptureRecord<'a> {
    // Crates a capture record with its position in the capture stream.
    pub(crate) fn new(packet_number: u64, data: &'a [u8]) -> Self {
        Self {
            packet_number,
            data,
        }
    }

    // Returns the sequential packet number assigned by CaptureReader.
    pub fn packet_number(&self) -> u64 {
        self.packet_number
    }

    // Returns the borrowed packet bytes without copying them.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::CaptureRecord;

    #[test]
    fn stores_packet_number_and_data() {
        let bytes = [0x01, 0x02, 0x03];

        // The capture record should preserve packet ordering metadata
        // while borrowing the original packet bytes.
        let record = CaptureRecord::new(42, &bytes);

        assert_eq!(record.packet_number(), 42);
        assert_eq!(record.data(), &bytes);
    }
}
