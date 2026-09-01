use std::fs::File;
use std::io;

pub struct RetainedPathHandles {
    pub(super) handles: Vec<File>,
    pub(super) target_exists: bool,
}

impl RetainedPathHandles {
    pub fn handles(&self) -> &[File] {
        &self.handles
    }

    pub fn target_exists(&self) -> bool {
        self.target_exists
    }

    pub fn target(&self) -> io::Result<&File> {
        if !self.target_exists {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "path target does not exist",
            ));
        }
        self.handles
            .last()
            .ok_or_else(|| io::Error::other("retained path has no target handle"))
    }

    pub fn target_mut(&mut self) -> io::Result<&mut File> {
        if !self.target_exists {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "path target does not exist",
            ));
        }
        self.handles
            .last_mut()
            .ok_or_else(|| io::Error::other("retained path has no target handle"))
    }

    pub fn into_target(mut self) -> io::Result<File> {
        if !self.target_exists {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "path target does not exist",
            ));
        }
        self.handles
            .pop()
            .ok_or_else(|| io::Error::other("retained path has no target handle"))
    }
}
