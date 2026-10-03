use std::{
    fs::File,
    path::{Path, PathBuf},
};

use pcap_parser::{PcapBlockOwned, PcapError, pcap::LegacyPcapReader, traits::PcapReaderIterator};

use crate::capture::{
    CaptureCompletion, CaptureProcessError, CaptureRecord, CaptureTerminationReason,
    CaptureTimestamp,
};

use super::CaptureError;

const BUFFER_CAPACITY: usize = 65_536;

pub struct CaptureReader {
    path: PathBuf,
}

impl CaptureReader {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CaptureError> {
        let path = path.as_ref().to_path_buf();

        // Valdidate the source when the reader is created so an invalid path
        // fails immediately instead of much later during processing.
        Self::open_file(&path)?;

        Ok(Self { path })
    }

    pub fn packet_count(&self) -> Result<(u64, CaptureCompletion), CaptureError> {
        let mut packet_count = 0;

        let completion = self
            .process(|_| {
                packet_count += 1;

                Ok::<(), std::convert::Infallible>(())
            })
            .map_err(|error| match error {
                CaptureProcessError::Capture(error) => error,

                // The counting handler is infallible, so this branch is
                // unreachable by construction/
                CaptureProcessError::Handler(never) => match never {},
            })?;

        Ok((packet_count, completion))
    }

    // Processes every Legacy PCAP packet in the capture.
    //
    // packet data is borrowed only for the duration of the handler call.
    // The handler must not retain the borrowed data after returning.
    //
    // This matches the lifecycle required by `pcap-parser`: after a block
    // has been handled, its consumed bytes can be released so the parser
    // can continue streaming without copying every packet into a new buffer.
    pub fn process<F, E>(&self, mut handler: F) -> Result<CaptureCompletion, CaptureProcessError<E>>
    where
        F: FnMut(CaptureRecord<'_>) -> Result<(), E>,
    {
        let file = Self::open_file(&self.path).map_err(CaptureProcessError::Capture)?;

        let mut reader = LegacyPcapReader::new(BUFFER_CAPACITY, file).map_err(|error| {
            CaptureProcessError::Capture(CaptureError::Parse {
                message: format!("{error:?}"),
            })
        })?;

        let mut packet_number = 0_u64;

        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    if let PcapBlockOwned::Legacy(packet) = block {
                        // Advance the packet number only when a real packet record is encountered.
                        packet_number += 1;

                        // `CaptureRecord` borrows packet bytes only whle
                        // `packet` remains alive in this iteration.
                        let record = CaptureRecord::new(
                            packet_number,
                            &packet.data,
                            CaptureTimestamp::new(packet.ts_sec, packet.ts_usec),
                            packet.origlen,
                        );

                        handler(record).map_err(CaptureProcessError::Handler)?;
                    }

                    // Tell pcap-parser that the current block is no longer needed.
                    // This allows its internal streaming buffer to
                    // advance and eventually reuse consumed memory.
                    reader.consume(offset);
                }

                // A clean end of the capture is normal termination.
                Err(PcapError::Eof) => break,

                // The current buffer does not contain enough bytes yet.
                // Refill lets the streaming reader read more input.
                Err(PcapError::Incomplete(_)) => reader.refill().map_err(|error| {
                    CaptureProcessError::Capture(CaptureError::Parse {
                        message: format!("{error:?}"),
                    })
                })?,

                // The capture ended unexpectedly after valid records had already
                // been processed. The caller can keep the accumulated results, but
                // must treat the overall capture analysis as partial
                Err(PcapError::UnexpectedEof) => {
                    return Ok(CaptureCompletion::Partial {
                        reason: CaptureTerminationReason::UnexpectedEof,
                    });
                }

                // Malformed or otherwise invalid capture input must be
                // returned as an error instead of causing a panic.
                Err(error) => {
                    return Err(CaptureProcessError::Capture(CaptureError::Parse {
                        message: format!("{error:?}"),
                    }));
                }
            }
        }
        Ok(CaptureCompletion::Complete)
    }

    // Opens the capture source without expasing file handling
    // outsite the capture module
    fn open_file(path: &Path) -> Result<File, CaptureError> {
        File::open(path).map_err(|source| CaptureError::Io {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_path(name: &str) -> String {
        format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn counts_packets_from_sample_capture() {
        let reader = CaptureReader::open(fixture_path("sample.pcap"))
            .expect("sample capture fixture should open successfully");

        let (count, completion) = reader
            .packet_count()
            .expect("sample capture fixture should be parsed successfully");

        assert_eq!(count, 963);
        assert_eq!(completion, CaptureCompletion::Complete)
    }

    #[test]
    fn processes_every_packet_from_sample_capture() {
        let reader = CaptureReader::open(fixture_path("sample.pcap"))
            .expect("sample capture fixture should open successfully");

        let mut processed_packets = 0;

        let completion = reader
            .process(|record| {
                // Accessing the proves that the callback receives
                // an actual borrowed packet record.
                assert!(!record.data().is_empty());

                processed_packets += 1;

                Ok::<(), ()>(())
            })
            .expect("sample capture fixture should be processed successfully");

        assert_eq!(processed_packets, 963);
        assert_eq!(completion, CaptureCompletion::Complete)
    }

    #[test]
    fn fails_when_capture_file_does_not_exist() {
        // The reader should fail during source validation rather than allowing
        // a missing capture file to reach the processing stage.
        let result = CaptureReader::open("tests/fixtures/this-file-does-not-exist.pcap");

        assert!(
            matches!(result, Err(CaptureError::Io { .. })),
            "a missing capture file should return CaptureError::Io"
        );
    }

    #[derive(Debug, PartialEq, Eq)]
    enum TestHandlerError {
        IntentionalFailure,
    }

    #[test]
    fn propagates_handler_errors() {
        let reader = CaptureReader::open(fixture_path("sample.pcap"))
            .expect("sample capture fixture should open successfully");

        let result = reader.process(|_| Err::<(), _>(TestHandlerError::IntentionalFailure));

        assert!(
            matches!(
                result,
                Err(CaptureProcessError::Handler(
                    TestHandlerError::IntentionalFailure
                ))
            ),
            "handler errors should remain distinguishable from capture errors"
        );
    }

    #[test]
    fn fails_gracefully_on_malformed_captured() {
        let reader = CaptureReader::open(fixture_path("malformed.pcap"))
            .expect("malformed fixture should still be a readable file");

        let result = reader.process(|_| Ok::<(), ()>(()));

        assert!(
            matches!(
                result,
                Err(CaptureProcessError::Capture(CaptureError::Parse { .. }))
            ),
            "malformed capture input should return a capture parse error"
        );
    }

    #[test]
    fn observes_truncated_capture_behavior() {
        let reader = CaptureReader::open(fixture_path("truncated.pcap"))
            .expect("truncated fixture should still be readable");

        let mut processed_packets = 0;

        let result = reader.process(|_| {
            processed_packets += 1;

            Ok::<(), ()>(())
        });

        println!("processed packets: {processed_packets}, result: {result:?}");
    }

    #[test]
    fn completes_partially_when_capture_ends_unexpected() {
        let reader = CaptureReader::open(fixture_path("truncated.pcap"))
            .expect("truncated fixture should still be a readable file");

        let mut processed_packets = 0;

        let completion = reader
            .process(|_| {
                processed_packets += 1;

                Ok::<(), ()>(())
            })
            .expect("truncated capture should produce a partial completion");

        assert_eq!(processed_packets, 961);

        assert_eq!(
            completion,
            CaptureCompletion::Partial {
                reason: CaptureTerminationReason::UnexpectedEof
            }
        )
    }

    #[test]
    fn assigns_sequential_packet_numbers() {
        let reader = CaptureReader::open(fixture_path("sample.pcap"))
            .expect("sample capture fixture should open successfully");

        let mut packet_numbers = Vec::new();

        let completion = reader
            .process(|record| {
                // CaptureReader owns the packet sequence, so packet numbers
                // must increase monotonically for every captured packet.
                packet_numbers.push(record.packet_number());

                Ok::<(), ()>(())
            })
            .expect("sample capture should process successfully");

        assert_eq!(completion, CaptureCompletion::Complete);

        // The first packets should be numbered from one, not zero.
        assert_eq!(&packet_numbers[..3], &[1, 2, 3]);

        // The sample capture contains 963 packets.
        assert_eq!(packet_numbers.len(), 963);

        // The final packet should therefore have number 963.
        assert_eq!(packet_numbers.last(), Some(&963));

        // Every packet number should be unique and sequential.
        for (index, packet_number) in packet_numbers.iter().enumerate() {
            assert_eq!(*packet_number, (index + 1) as u64);
        }
    }
}
