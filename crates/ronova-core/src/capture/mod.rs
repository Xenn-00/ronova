mod error;
mod reader;
mod record;

pub use error::{CaptureCompletion, CaptureError, CaptureProcessError, CaptureTerminationReason};
pub use reader::CaptureReader;
pub use record::CaptureRecord;

#[cfg(test)]
mod tests {
    use super::{
        CaptureCompletion, CaptureError, CaptureProcessError, CaptureReader,
        CaptureTerminationReason,
    };

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
}
