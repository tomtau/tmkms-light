//! Validator configuration
//! Copyright (c) 2018-2021 Iqlusion Inc. (licensed under the Apache License, Version 2.0)
//! Modifications Copyright (c) 2021-present, Crypto.com (licensed under the Apache License, Version 2.0)

use serde::{Deserialize, Serialize};
use tendermint::chain;

/// Validator configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorConfig {
    /// Chain ID of the Tendermint network this validator is part of
    pub chain_id: chain::Id,

    /// Height at which to stop signing
    pub max_height: Option<tendermint::block::Height>,
}
