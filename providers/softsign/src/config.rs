use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, path::PathBuf};
use tendermint::{chain, net};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftSignOpt {
    /// Address of the validator (`tcp://` or `unix://`)
    pub address: net::Address,
    /// Chain ID of the Tendermint network this validator is part of
    pub chain_id: chain::Id,
    /// Height at which to stop signing
    pub max_height: Option<tendermint::block::Height>,
    /// Path to a file containing a cryptographic key
    pub consensus_key_path: PathBuf,
    /// Path to our Ed25519 identity key (if applicable)
    pub id_key_path: Option<PathBuf>,
    /// Path to chain-specific `priv_validator_state.json` file
    pub state_file_path: PathBuf,
    /// Optional timeout value in seconds
    pub timeout: Option<u16>,
    /// Retry connection
    pub retry: bool,
}

impl Default for SoftSignOpt {
    fn default() -> Self {
        Self {
            address: net::Address::Unix {
                path: "/tmp/validator.socket".into(),
            },
            chain_id: chain::Id::try_from("testchain-1".to_owned()).expect("valid chain-id"),
            max_height: None,
            consensus_key_path: "secrets/secret.key".into(),
            id_key_path: Some("secrets/id.key".into()),
            state_file_path: "state/priv_validator_state.json".into(),
            timeout: None,
            retry: true,
        }
    }
}
