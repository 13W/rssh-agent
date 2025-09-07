use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Agent is locked")]
    Locked,

    #[error("Agent not initialized")]
    NotInitialized,

    #[error("Agent already running")]
    AlreadyRunning,

    #[error("Socket already in use")]
    AlreadyInUse,

    #[error("Access denied")]
    AccessDenied,

    #[error("Operation not supported")]
    Unsupported,

    #[error("Operation timed out")]
    Timeout,

    #[error("Too many keys loaded (max: 1024)")]
    TooManyKeys,

    #[error("Invalid arguments")]
    BadArgs,

    #[error("Wrong master password")]
    WrongPassword,

    #[error("Master unlock required")]
    NeedMasterUnlock,

    #[error("Key not found")]
    NotFound,

    #[error("Key already loaded")]
    AlreadyLoaded,

    #[error("Key not loaded")]
    NotLoaded,

    #[error("Already exists")]
    AlreadyExists,

    #[error("Fingerprint mismatch")]
    FingerprintMismatch,

    #[error("RSA key too small (minimum 2048 bits)")]
    RsaTooSmall,

    #[error("RSA key too large (maximum 8192 bits)")]
    RsaTooLarge,

    #[error("Socket not found")]
    NoSocket,

    #[error("Already initialized")]
    AlreadyInitialized,

    #[error("Not implemented")]
    NotImplemented,

    #[error("Key requires password")]
    NeedKeyPassword,

    #[error("Wrong key password")]
    BadKeyPassword,

    #[error("Invalid certificate format")]
    BadCertFormat,

    #[error("Certificate does not match key")]
    CertMismatch,

    #[error("Not an external key")]
    NotExternal,

    #[error("No disk entry for this key")]
    NoDiskEntry,

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Config(e.to_string())
    }
}

impl Error {
    /// Map error to exit code according to spec
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::BadArgs => 2,
            Error::NoSocket => 3,
            Error::AlreadyRunning | Error::AlreadyInUse => 4,
            Error::Locked | Error::NeedMasterUnlock => 5,
            Error::WrongPassword | Error::BadKeyPassword => 6,
            Error::NotInitialized | Error::AlreadyInitialized => 7,
            Error::Unsupported | Error::NotImplemented => 8,
            Error::Timeout | Error::Io(_) => 9,
            Error::AccessDenied => 10,
            Error::TooManyKeys => 11,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_code_mapping() {
        assert_eq!(Error::BadArgs.exit_code(), 2);
        assert_eq!(Error::NoSocket.exit_code(), 3);
        assert_eq!(Error::AlreadyRunning.exit_code(), 4);
        assert_eq!(Error::AlreadyInUse.exit_code(), 4);
        assert_eq!(Error::Locked.exit_code(), 5);
        assert_eq!(Error::NeedMasterUnlock.exit_code(), 5);
        assert_eq!(Error::WrongPassword.exit_code(), 6);
        assert_eq!(Error::BadKeyPassword.exit_code(), 6);
        assert_eq!(Error::NotInitialized.exit_code(), 7);
        assert_eq!(Error::AlreadyInitialized.exit_code(), 7);
        assert_eq!(Error::Unsupported.exit_code(), 8);
        assert_eq!(Error::NotImplemented.exit_code(), 8);
        assert_eq!(Error::Timeout.exit_code(), 9);
        assert_eq!(
            Error::Io(std::io::Error::new(std::io::ErrorKind::Other, "test")).exit_code(),
            9
        );
        assert_eq!(Error::AccessDenied.exit_code(), 10);
        assert_eq!(Error::TooManyKeys.exit_code(), 11);

        // Default cases
        assert_eq!(Error::Config("test".into()).exit_code(), 1);
        assert_eq!(Error::Crypto("test".into()).exit_code(), 1);
        assert_eq!(Error::NotFound.exit_code(), 1);
    }

    #[test]
    fn test_error_display_no_secrets() {
        let err = Error::WrongPassword;
        let display = format!("{}", err);
        assert_eq!(display, "Wrong master password");
        // Note: The error message contains "password" but doesn't expose actual password values

        let err = Error::Crypto("test error".into());
        let display = format!("{}", err);
        assert_eq!(display, "Cryptographic error: test error");
    }
}
