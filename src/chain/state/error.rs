//! Error types regarding chain state (i.e. double signing)

use anomaly::{BoxError, Context};
use thiserror::Error;

pub type StateError = anomaly::Error<StateErrorKind>;

/// Kinds of errors
#[derive(Copy, Clone, Debug, Error, Eq, PartialEq)]
pub enum StateErrorKind {
    /// Height regressed
    #[error("height regression")]
    HeightRegression,

    /// Step regressed
    #[error("step regression")]
    StepRegression,

    /// Round regressed
    #[error("round regression")]
    RoundRegression,

    /// Double sign detected
    #[error("double sign detected")]
    DoubleSign,

    /// Error syncing state
    #[error("error syncing state")]
    SyncError,
}

impl StateErrorKind {
    /// Add additional context (i.e. include a source error and capture
    /// a backtrace).
    ///
    /// You can convert the resulting `Context` into an `Error` by calling
    /// `.into()`.
    pub fn context(self, source: impl Into<BoxError>) -> Context<StateErrorKind> {
        Context::new(self, Some(source.into()))
    }
}
