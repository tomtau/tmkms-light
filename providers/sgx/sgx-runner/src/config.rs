use crate::shared::SealedKeyData;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, path::PathBuf};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
use tendermint::{chain, net};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SgxSignOpt {
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
    /// Path to sgxs + signature files
    pub enclave_path: PathBuf,
}

impl Default for SgxSignOpt {
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
            enclave_path: "enclave/tmkms-light-sgx-app.sgxs".into(),
        }
    }
}

/// write sealed key data
pub fn write_sealed_file<P: AsRef<Path>>(path: P, sealed_data: &SealedKeyData) -> io::Result<()> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path.as_ref())
        .and_then(|mut file| {
            file.write_all(&bincode::serialize(sealed_data).expect("serialize sealed data"))
        })
}
