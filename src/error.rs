//! Error types
//! Copyright (c) 2018-2021 Iqlusion Inc. (licensed under the Apache License, Version 2.0)
//! Modifications Copyright (c) 2021, Foris Limited (licensed under the Apache License, Version 2.0)

use flex_error::define_error;
use flex_error::DetailOnly;

define_error! {
    Error {
        SigningTendermintError { error: String }
        [ DetailOnly<tendermint_proto::Error> ]
        |e| {
            e.error
        },
        SigningStateError { error: String }
        [ DetailOnly<crate::chain::state::StateError> ]
        |e| {
            e.error
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

        ConfigError {
        } |_| {
            "Config Error"
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

        CryptoError {
        } |_| {
            "cryptographic error"
        },

        HookError {
        } |_| {
            "subcommand hook failed"
        },

        InvalidKeyError {
        } |_| {
            "invalid key"
        },

        InvalidMessageError {
        } |_| {
        "invalid consensus message"
        },

        IoError { error: String }
        [ DetailOnly<std::io::Error> ]
        |e| {
            e.error
        },

        PanicError {
        } |_| {
            "internal crash"
        },

        ParseError {
        } |_| {
            "parse error"
        },

        PoisonError {
        } |_| {
            "internal state poisoned"
        },

        ProtocolError { error: String }
        [ DetailOnly<std::io::Error> ]
        |e| {
            e.error
        },

        SerializationError {
        } |_| {
            "serialization error"
        },

        TendermintError {
        } |_| {
            "Tendermint error"
        },

        VerificationError {
        } |_| {
            "verification failed"
        }
    }
}
