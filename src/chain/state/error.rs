//! Error types regarding chain state (i.e. double signing)
//! Copyright (c) 2018-2021 Iqlusion Inc. (licensed under the Apache License, Version 2.0)
//! Modifications Copyright (c) 2021-present, Crypto.com (licensed under the Apache License, Version 2.0)

use flex_error::{define_error, DetailOnly};
use tendermint::block::{Height, Round};

define_error! {
    StateError {
        HeightRegressionError {
            last_height: Height,
            new_height: Height,
        }
        |e| {
            format_args!("last height:{} new height:{}", e.last_height, e.new_height)
        },

        RoundRegressionError {
            height: Height,
            last_round: Round,
            new_round: Round,
        } |e| {
            format_args!("round regression at height:{} last round:{} new round:{}", e.height, e.last_round, e.new_round)
        },

        StepRegressionError {
            height: Height,
            round: Round,
            last_step: i8,
            new_step: i8,
        } |e| {
            format_args!("round regression at height:{} round:{} last step:{} new step:{}", e.height, e.round, e.last_step, e.new_step)
        },
        DoubleSignError{
            height: Height,
            round: Round,
            step: i8,
            old_block_id: String,
            new_block_id: String,
        } |e| {
            format_args!("Attempting to sign a second proposal at height:{} round:{} step:{} old block id:{} new block {}", e.height, e.round, e.step, e.old_block_id, e.new_block_id)
        },
        SyncError{
            path: String,
        } [DetailOnly<std::io::Error>] |e| {
            format_args!("Error syncing {}", e.path)
        },
        SyncEncDecError{
            path_or_msg: String,
        } [DetailOnly<serde_json::Error>] |e| {
            format_args!("Error parsing or serializing in syncing {}", e.path_or_msg)
        },
        SyncOtherError{
            error_message: String,
        } |e| {
            format_args!("Error state syncing: {}", e.error_message)
        },
    }
}
