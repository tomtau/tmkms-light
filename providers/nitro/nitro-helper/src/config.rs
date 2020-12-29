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
    /// Vsock port to forward privval plain traffic to TM over UDS
    pub enclave_tendermint_conn: Option<u32>,
    /// AWS credentials -- if not set, they'll be obtained from IAM
    pub credentials: Option<AwsCredentials>,
    /// AWS region
    pub aws_region: String,
}

/// Credentials, generally obtained from parent instance IAM
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsCredentials {
    /// AccessKeyId
    pub aws_key_id: String,
    /// SecretAccessKey
    pub aws_secret_key: String,
    /// SessionToken
    pub aws_session_token: String,
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
            enclave_tendermint_conn: None,
            credentials: None,
            aws_region: "ap-southeast-1".to_owned(),
        }
    }
}

// write sealed key data
// pub fn write_sealed_file<P: AsRef<Path>>(path: P, sealed_data: &SealedKeyData) -> io::Result<()> {
//     OpenOptions::new()
//         .create(true)
//         .write(true)
//         .truncate(true)
//         .mode(0o600)
//         .open(path.as_ref())
//         .and_then(|mut file| {
//             file.write_all(&bincode::serialize(sealed_data).expect("serialize sealed data"))
//         })
// }
