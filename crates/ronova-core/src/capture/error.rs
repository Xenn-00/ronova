use std::path::PathBuf;

#[derive(Debug)]
pub enum CaptureError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    Parse {
        message: String,
    },
}

// Describes how capture processing ended.
//
// A Partial completion means that some records were processed successfully,
// but the capture could not be processed until normal completion.
#[derive(Debug, PartialEq, Eq)]
pub enum CaptureCompletion {
    Complete,

    Partial { reason: CaptureTerminationReason },
}

// Describes why capture processing stopped before normal completion.
#[derive(Debug, PartialEq, Eq)]
pub enum CaptureTerminationReason {
    UnexpectedEof,
}

// Represents an error that occured while processing a capture.
//
// Capture failures and consumer failures are kept seperate so callers
// can distinguish whether the capture source itself failed or the
// downstream processing pipeline rejected a record.

#[derive(Debug)]
pub enum CaptureProcessError<E> {
    Capture(CaptureError),
    Handler(E),
}
