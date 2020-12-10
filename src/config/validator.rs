//! Validator configuration

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
