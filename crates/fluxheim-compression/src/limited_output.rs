use std::io;
use std::mem;

use bytes::Bytes;

#[derive(Clone, Copy, Debug)]
enum LimitedOutputFailure {
    Limit,
    Allocation,
}

#[derive(Debug)]
pub(super) struct LimitedOutput {
    buffer: Vec<u8>,
    remaining: usize,
    total_written: usize,
    failure: Option<LimitedOutputFailure>,
}

impl LimitedOutput {
    pub(super) fn new(max_output_bytes: usize) -> Self {
        Self {
            buffer: Vec::new(),
            remaining: max_output_bytes,
            total_written: 0,
            failure: None,
        }
    }

    pub(super) fn take_bytes(&mut self) -> io::Result<Bytes> {
        self.ensure_healthy()?;
        Ok(Bytes::from(mem::take(&mut self.buffer)))
    }

    pub(super) fn into_bytes(self) -> io::Result<(Bytes, usize)> {
        self.ensure_healthy()?;
        Ok((Bytes::from(self.buffer), self.total_written))
    }

    pub(super) fn total_written(&self) -> usize {
        self.total_written
    }

    #[cfg(test)]
    pub(super) fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    fn ensure_healthy(&self) -> io::Result<()> {
        match self.failure {
            None => Ok(()),
            Some(failure) => Err(failure.error()),
        }
    }

    fn fail(&mut self, failure: LimitedOutputFailure) -> io::Error {
        self.failure.get_or_insert(failure).error()
    }
}

impl io::Write for LimitedOutput {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.ensure_healthy()?;
        if input.len() > self.remaining {
            return Err(self.fail(LimitedOutputFailure::Limit));
        }
        let next_total = self
            .total_written
            .checked_add(input.len())
            .ok_or_else(|| self.fail(LimitedOutputFailure::Limit))?;
        if self.buffer.try_reserve(input.len()).is_err() {
            return Err(self.fail(LimitedOutputFailure::Allocation));
        }
        self.buffer.extend_from_slice(input);
        self.remaining -= input.len();
        self.total_written = next_total;
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.ensure_healthy()
    }
}

impl LimitedOutputFailure {
    fn error(self) -> io::Error {
        match self {
            Self::Limit => io::Error::new(
                io::ErrorKind::InvalidData,
                "compressed response exceeds max_output_bytes",
            ),
            Self::Allocation => io::Error::new(
                io::ErrorKind::OutOfMemory,
                "unable to allocate compressed response buffer",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::LimitedOutput;

    #[test]
    fn refuses_output_before_growing_past_limit() {
        let mut output = LimitedOutput::new(4);
        output.write_all(b"1234").unwrap();
        let error = output.write_all(b"5").unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(output.buffer, b"1234");
        assert_eq!(output.total_written, 4);
        assert!(output.take_bytes().is_err());
    }
}
