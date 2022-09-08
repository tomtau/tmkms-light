use crate::shared::CloudBackupKeyData;
use crate::shared::SealedKeyData;
use clap::StructOpt;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, path::PathBuf};
use std::{fs::OpenOptions, io, os::unix::fs::OpenOptionsExt, path::Path};
use tendermint::chain;
use tendermint_config::net;
use tmkms_light::utils::PubkeyDisplay;
use tracing::error;

/// runner configuration in toml
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

fn write_json_file<P: AsRef<Path>, T: ?Sized + Serialize>(path: P, data: &T) -> io::Result<()> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path.as_ref())
        .and_then(|file| {
            serde_json::to_writer(file, data).map_err(|e| {
                error!(
                    "failed to write key (backup or sealed) data payload: {:?}",
                    e
                );
                io::ErrorKind::Other.into()
            })
        })
}

/// write sealed key data
pub fn write_sealed_file<P: AsRef<Path>>(path: P, sealed_data: &SealedKeyData) -> io::Result<()> {
    write_json_file(path, sealed_data)
}

/// write backup key data
pub fn write_backup_file<P: AsRef<Path>>(
    path: P,
    sealed_data: &CloudBackupKeyData,
) -> io::Result<()> {
    write_json_file(path, sealed_data)
}

#[derive(StructOpt, Debug)]
pub struct RecoverConfig {
    #[structopt(short)]
    pub config_path: Option<PathBuf>,
    #[structopt(short)]
    pub pubkey_display: Option<PubkeyDisplay>,
    #[structopt(short)]
    pub bech32_prefix: Option<String>,
    #[structopt(short)]
    pub wrap_backup_key_path: PathBuf,
    #[structopt(short)]
    pub external_cloud_key_path: PathBuf,
    #[structopt(short)]
    pub key_backup_data_path: PathBuf,
    #[structopt(short)]
    pub recover_consensus_key: bool,
}
