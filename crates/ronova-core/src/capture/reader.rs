use std::{
    fs::File,
    path::{Path, PathBuf},
};

use pcap_parser::{PcapBlockOwned, PcapError, pcap::LegacyPcapReader, traits::PcapReaderIterator};

use crate::capture::{
    CaptureCompletion, CaptureProcessError, CaptureRecord, CaptureTerminationReason,
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

        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    if let PcapBlockOwned::Legacy(packet) = block {
                        // `CaptureRecord` borrows packet bytes only whle
                        // `packet` remains alive in this iteration.
                        let record = CaptureRecord::new(&packet.data);

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
