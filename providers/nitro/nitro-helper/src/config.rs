use crate::shared::AwsCredentials;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, path::PathBuf};
use tendermint::{chain, net};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NitroSignOpt {
    /// Address of the validator (`tcp://` or `unix://`)
    pub address: net::Address,
    /// Chain ID of the Tendermint network this validator is part of
    pub chain_id: chain::Id,
    /// Height at which to stop signing
    pub max_height: Option<tendermint::block::Height>,
    /// Path to a file containing a cryptographic key
    pub sealed_consensus_key_path: PathBuf,
    /// Path to our Ed25519 identity key (if applicable)
    pub sealed_id_key_path: Option<PathBuf>,
    /// Path to chain-specific `priv_validator_state.json` file
    pub state_file_path: PathBuf,
    /// Vsock cid to push config to
    pub enclave_config_cid: u32,
    /// Vsock port to push config to
    pub enclave_config_port: u32,
    /// Vsock port to listen on for state synchronization
    pub enclave_state_port: u32,
    /// Vsock port to forward privval plain traffic to TM over UDS (or just pass to enclave if TCP/secret connection)
    pub enclave_tendermint_conn: u32,
    /// AWS credentials -- if not set, they'll be obtained from IAM
    pub credentials: Option<AwsCredentials>,
    /// AWS region
    pub aws_region: String,
}

impl Default for NitroSignOpt {
    fn default() -> Self {
        Self {
            address: net::Address::Unix {
                path: "/tmp/validator.socket".into(),
            },
            chain_id: chain::Id::try_from("testchain-1".to_owned()).expect("valid chain-id"),
            max_height: None,
            sealed_consensus_key_path: "secrets/secret.key".into(),
            sealed_id_key_path: Some("secrets/id.key".into()),
            state_file_path: "state/priv_validator_state.json".into(),
            enclave_config_cid: 15,
            enclave_config_port: 5050,
            enclave_state_port: 5555,
            enclave_tendermint_conn: 5000,
            credentials: None,
            aws_region: "ap-southeast-1".to_owned(),
        }
    }
}
