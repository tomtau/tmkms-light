use crate::shared::AwsCredentials;
use serde::{Deserialize, Serialize};
use std::fs;
use std::{convert::TryFrom, path::PathBuf};
use structopt::StructOpt;
use tendermint::{chain, net};

/// nitro options for toml configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl NitroSignOpt {
    pub fn from_file(config_path: PathBuf) -> Result<Self, String> {
        let toml_string = std::fs::read_to_string(config_path)
            .map_err(|e| format!("toml config file failed to read: {:?}", e))?;
        toml::from_str(&toml_string)
            .map_err(|e| format!("toml config file failed to parse: {:?}", e))
    }
}

#[derive(StructOpt, Clone, Serialize, Deserialize, Debug)]
pub struct VSockProxyOpt {
    /// "Set the maximum number of simultaneous connections supported."
    #[structopt(long, short = "w", default_value = "4")]
    pub num_workers: usize,
    /// "Local vsock port to listen for incoming connections."
    #[structopt(long, default_value = "8000")]
    pub local_port: u32,
    /// "Remote TCP port of the server to be proxyed."
    #[structopt(long, default_value = "443")]
    pub remote_port: u16,
    /// "Address of the server to be proxyed."
    #[structopt(long)]
    pub remote_addr: String,
    /// "YAML file containing the services that can be forwarded.\n"
    #[structopt(long, default_value = "/etc/nitro_enclaves/vsock-proxy.yaml")]
    pub config_file: String,
}

impl Default for VSockProxyOpt {
    fn default() -> Self {
        Self {
            num_workers: 4,
            local_port: 8000,
            remote_port: 443,
            remote_addr: "kms.ap-southeast-1.amazonaws.com".to_string(),
            config_file: "/etc/nitro_enclaves/vsock-proxy.yaml".to_string(),
        }
    }
}

#[derive(StructOpt, Clone, Serialize, Deserialize, Debug)]
pub struct EnclaveOpt {
    /// The path to the enclave image file
    #[structopt(long, short = "p", default_value = "/home/ec2-user/.tmkms/tmkms.eif")]
    pub eif_path: String,
    /// The optional enclave CID
    #[structopt(long, short = "i")]
    pub enclave_cid: Option<u64>,
    /// The amount of memory that will be given to the enclave.
    #[structopt(long, default_value = "512")]
    pub memory_mib: u64,
    /// The number of CPUs that the enclave will receive.
    #[structopt(long, conflicts_with("cpu_ids"))]
    pub cpu_count: usize,
    /// Set the enclave log server port
    #[structopt(long, default_value = "6050")]
    pub log_server_port: u32,
    /// Set the enclave log file
    #[structopt(long)]
    pub log_file: Option<PathBuf>,
    /// output the enclave to console
    #[structopt(long, short = "l")]
    pub log_to_console: bool,
}

impl Default for EnclaveOpt {
    fn default() -> Self {
        Self {
            eif_path: "tmkms.eif".to_string(),
            enclave_cid: None,
            memory_mib: 512,
            cpu_count: 2,
            log_server_port: 6050,
            log_file: None,
            log_to_console: true,
        }
    }
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

/// the config to run the enclave and vsock proxy
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct EnclaveConfig {
    pub vsock_proxy: VSockProxyOpt,
    pub enclave: EnclaveOpt,
}

impl EnclaveConfig {
    pub fn from_file(config_path: PathBuf) -> Result<Self, String> {
        if !config_path.exists() {
            return Err("config path is not exists".to_string());
        }
        let toml_string = fs::read_to_string(config_path).expect("toml config file read");
        toml::from_str(&toml_string)
            .map_err(|e| format!("toml config file failed to parse: {:?}", e))
    }
}
