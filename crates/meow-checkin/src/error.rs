//! A refused call: what kind of refusal, and one sentence for the user.

use std::fmt;

/// Why a call was refused; the API maps it to the HTTP status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// No such task, variable or click request.
    NotFound,
    /// The input is not acceptable.
    Invalid,
    /// The input is fine but cannot be applied now (name taken, variables
    /// unfilled).
    Conflict,
    /// The input is larger than the limits allow.
    TooLarge,
    /// The change could not be written to disk.
    Storage,
}

/// A refused call. `message` is a complete sentence the app shows as is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckinError {
    pub kind: ErrorKind,
    pub message: String,
}

impl CheckinError {
    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::NotFound,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Invalid,
            message: message.into(),
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Conflict,
            message: message.into(),
        }
    }

    pub fn too_large(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::TooLarge,
            message: message.into(),
        }
    }
}

impl CheckinError {
    pub fn storage() -> Self {
        Self {
            kind: ErrorKind::Storage,
            message: "保存失败：写不了签到助手的数据文件。".to_string(),
        }
    }
}

impl fmt::Display for CheckinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CheckinError {}

pub type Result<T> = std::result::Result<T, CheckinError>;
