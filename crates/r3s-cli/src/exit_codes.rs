//! Standardized exit codes for the r3s CLI.

/// Standardized exit codes for the r3s CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Command succeeded.
    Success = 0,
    /// Generic error.
    GenericError = 1,
    /// Resource not found.
    NotFound = 2,
    /// Permission denied.
    PermissionDenied = 3,
    /// Invalid argument provided.
    InvalidArgument = 4,
    /// Conflict (e.g., container already exists).
    Conflict = 5,
}

impl ExitCode {
    /// Convert exit code to i32 for use with `std::process::exit`.
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}
