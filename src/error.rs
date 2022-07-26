//! Error types
//! Copyright (c) 2018-2021 Iqlusion Inc. (licensed under the Apache License, Version 2.0)
//! Modifications Copyright (c) 2021-present, Crypto.com (licensed under the Apache License, Version 2.0)

use flex_error::define_error;
use flex_error::DetailOnly;

define_error! {
    Error {
        SigningTendermintError { error: String }
        [ DetailOnly<tendermint_proto::Error> ]
        |e| {
            e.error.clone()
        },
        SigningStateError { error: String }
        [ DetailOnly<crate::chain::state::StateError> ]
        |e| {
            e.error.clone()
        },
        AccessError {
        } |_| {
            "Access Denied"
        },

        ChainIdError {
            chain_id: String,
        } |e| {
            format_args!("chain ID error: {}", e.chain_id)
        },

        DoubleSign {
        } |_| {
            "Attempted double sign"
        },

        ExceedMaxHeight {
            request_height: i64,
            max_height: u64,
        } |e| {
            format_args!("attempted to sign at height {} which is greater than {}", e.request_height, e.max_height)
        },

        InvalidKeyError {
        } |_| {
            "invalid key"
        },

        IoError { error: String }
        [ DetailOnly<std::io::Error> ]
        |e| {
            e.error.clone()
        },

        PanicError {
        } |_| {
            "internal crash"
        },

        ProtocolError { error: String }
        [ DetailOnly<std::io::Error> ]
        |e| {
            e.error.clone()
        },

        ProtocolErrorTendermint { error: String }
        [ DetailOnly<tendermint::Error> ]
        |e| {
            e.error.clone()
        },

        ProtocolErrorMsg { error: String }
        [ DetailOnly<std::option::Option<tendermint_proto::privval::message::Sum>> ]
        |e| {
            e.error.clone()
        },

        SerializationError {
        }  [ DetailOnly<serde_json::Error> ] |e| {
            format_args!("serialization error: {}", e)
        },

    }
}

/// Wraps IO-related error from a different source into an IO error
/// as a kind Other
pub fn io_error_wrap<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
    message: String,
    error: E,
) -> Error {
    Error::io_error(
        message,
        std::io::Error::new(std::io::ErrorKind::Other, error),
    )
}
