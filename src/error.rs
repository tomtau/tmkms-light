//! Error types
//! Copyright (c) 2018-2021 Iqlusion Inc. (licensed under the Apache License, Version 2.0)
//! Modifications Copyright (c) 2021, Foris Limited (licensed under the Apache License, Version 2.0)

use anomaly::{BoxError, Context};
use thiserror::Error;

/// Kinds of errors
#[derive(Copy, Clone, Eq, PartialEq, Debug, Error)]
pub enum ErrorKind {
    /// Access denied
    #[error("access denied")]
    AccessError,

    /// Invalid Chain ID
    #[error("chain ID error")]
    ChainIdError,

    /// Error in configuration file
    #[error("config error")]
    ConfigError,

    /// Double sign attempted
    #[error("attempted double sign")]
    DoubleSign,

    /// Request a signature above max height
    #[error("requested signature above stop height")]
    ExceedMaxHeight,

    /// Cryptographic operation failed
    #[error("cryptographic error")]
    CryptoError,

    /// Error running a subcommand to update chain state
    #[error("subcommand hook failed")]
    HookError,

    /// Malformatted or otherwise invalid cryptographic key
    #[error("invalid key")]
    InvalidKey,

    /// Validation of consensus message failed
    #[error("invalid consensus message")]
    InvalidMessageError,

    /// Input/output error
    #[error("I/O error")]
    IoError,

    /// KMS internal panic
    #[error("internal crash")]
    PanicError,

    /// Parse error
    #[error("parse error")]
    ParseError,

    /// KMS state has been poisoned
    #[error("internal state poisoned")]
    PoisonError,

    /// Network protocol-related errors
    #[error("protocol error")]
    ProtocolError,

    /// Serialization error
    #[error("serialization error")]
    SerializationError,

    /// Signing operation failed
    #[error("signing operation failed")]
    SigningError,

    /// Errors originating in the Tendermint crate
    #[error("Tendermint error")]
    TendermintError,

    /// Verification operation failed
    #[error("verification failed")]
    VerificationError,
}

impl ErrorKind {
    /// Add additional context (i.e. include a source error and capture
    /// a backtrace).
    ///
    /// You can convert the resulting `Context` into an `Error` by calling
    /// `.into()`.
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}

pub type Error = anomaly::Error<ErrorKind>;
