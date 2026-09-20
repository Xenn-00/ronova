#[derive(Debug)]
pub struct CaptureRecord<'a> {
    data: &'a [u8],
}

impl<'a> CaptureRecord<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }
}
