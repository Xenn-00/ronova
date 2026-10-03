// Represents the timestamp assigned to a packet by the capture format.
//
// Dieser eigene Typ hält die Capture-Zeit bewusst von einer externen
// Zeitbibliothek getrennt. So bleibt die Capture-Schicht einfach und
// unanbhängig von zusätzlichen Abhänhihkeiten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CaptureTimestamp {
    seconds: u64,
    microseconds: u32,
}

impl CaptureTimestamp {
    // Creates a capture timestamp from the values provided by the capture reader.
    //
    // Der Konstruktor nimmt genau die Zeitangaben auf, die das Capture-Format
    // liefert. Dadurch muss der Reader die Zeit nicht zuerst in einen anderen
    // Typ unwandeln.
    pub(crate) fn new(seconds: u32, microseconds: u32) -> Self {
        Self {
            seconds: u64::from(seconds),
            microseconds,
        }
    }

    // Returns the number of seconds since the capture timestamp epoch.
    pub fn seconds(&self) -> u64 {
        self.seconds
    }

    // Returns the microseconds part of the capture timestamp.
    pub fn microseconds(&self) -> u32 {
        self.microseconds
    }
}

// Represents one packet record read from a capture source.
//
// Ein CaptureRecord beschreibt immer einen echten Eintrag aus einer
// Capture-Datei. Deshalb gehören Zeitstempel und Originallänge direkt
// zum Record und sind keine optionalen Zusatzinformationen.
#[derive(Debug, Clone, Copy)]
pub struct CaptureRecord<'a> {
    // Sequential number assigned by the capture reader.
    packet_number: u64,

    // Borrowed packet bytes owned by the capture parser buffer.
    data: &'a [u8],

    // Timestamp assigned by the capture reader.
    timestamp: CaptureTimestamp,

    // Original packet length as reported by the capture reader.
    original_length: u32,
}

impl<'a> CaptureRecord<'a> {
    // Crates a capture record with all metadata provided by the capture reader.
    //
    // Ein Record soll nicht ohne Capture-Metadaten existieren. Dadurch bleibt
    // die Bedeutung dieses Typs eindeutig und spätere Verarbeitung kann sich auf
    // vollständige Metadaten Verlassen.
    pub(crate) fn new(
        packet_number: u64,
        data: &'a [u8],
        timestamp: CaptureTimestamp,
        original_length: u32,
    ) -> Self {
        Self {
            packet_number,
            data,
            timestamp,
            original_length,
        }
    }

    // Returns the sequential packet number assigned by CaptureReader.
    pub fn packet_number(&self) -> u64 {
        self.packet_number
    }

    // Returns the timestamp assigned by the capture reader.
    pub fn timestamp(&self) -> CaptureTimestamp {
        self.timestamp
    }

    // Returns the original packet length reported by the capture format.
    //
    // Die Originallänge kann größer als die tatsächlich gespeicherte Länge sein,
    // wenn das Capture abgeschnitten wurde. Beide Werte müssen deshalb getrennt
    // behandelt werden.
    pub fn original_length(&self) -> u32 {
        self.original_length
    }

    // Returns the number of packet bytes actually available in the capture.
    //
    // Für die bisherige Flow-Statistik verwenden wir bewusst die tatsächlich
    // erfassten Bytes. Die Originallänge ist eine separate Information.
    pub fn captured_length(&self) -> usize {
        self.data.len()
    }

    // Returns the borrowed packet bytes without copying them.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use crate::capture::CaptureTimestamp;

    use super::CaptureRecord;

    #[test]
    fn stores_packet_number_and_data() {
        let bytes = [0x01, 0x02, 0x03];

        // The capture record should preserve packet ordering metadata
        // while borrowing the original packet bytes.
        let record = CaptureRecord::new(
            42,
            &bytes,
            CaptureTimestamp {
                seconds: 1,
                microseconds: 1,
            },
            3,
        );

        assert_eq!(record.packet_number(), 42);
        assert_eq!(record.data(), &bytes);
        assert_eq!(
            record.timestamp(),
            CaptureTimestamp {
                seconds: 1,
                microseconds: 1
            }
        );
        assert_eq!(record.original_length(), 3);
        assert_eq!(record.captured_length(), 3);
    }

    #[test]
    fn synthetic_record_has_no_capture_metadata() {
        let data = [1, 2, 3, 4];

        let record = CaptureRecord::new(7, &data, CaptureTimestamp::new(1, 1), data.len() as u32);

        assert_eq!(record.packet_number(), 7);
        assert_eq!(record.timestamp(), CaptureTimestamp::new(1, 1));
        assert_eq!(record.original_length(), data.len() as u32);
        assert_eq!(record.captured_length(), data.len());
        assert_eq!(record.data(), &data);
    }

    #[test]
    fn metadata_record_preserves_capture_metadata() {
        let data = [1, 2, 3, 4];

        let timestamp = CaptureTimestamp::new(1_700_000_000, 123_456);

        let record = CaptureRecord::new(7, &data, timestamp, 1_500);

        assert_eq!(record.packet_number(), 7);
        assert_eq!(record.timestamp(), timestamp);
        assert_eq!(record.original_length(), 1_500);
        assert_eq!(record.captured_length(), data.len());
        assert_eq!(record.data(), &data);
    }

    #[test]
    fn capture_timestamp_exposes_seconds_and_microseconds() {
        let timestamp = CaptureTimestamp::new(1_700_000_000, 123_456);

        assert_eq!(timestamp.seconds(), 1_700_000_000);
        assert_eq!(timestamp.microseconds(), 123_456);
    }
}
