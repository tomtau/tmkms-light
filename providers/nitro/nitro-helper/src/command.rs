use crate::config::NitroSignOpt;
use crate::key_utils::generate_key;
use crate::proxy::Proxy;
use crate::shared::{AwsCredentials, NitroConfig};
use crate::state::StateSyncer;
use nix::sys::socket::SockAddr;
use rusoto_credential::{InstanceMetadataProvider, ProvideAwsCredentials};
use std::{fs, path::PathBuf};
use sysinfo::{ProcessExt, SystemExt};
use tendermint::net;
use tmkms_light::utils::write_u16_payload;
use tmkms_light::utils::{print_pubkey, PubkeyDisplay};
use tracing::{debug, Level};
use tracing_subscriber::FmtSubscriber;

/// write tmkms.toml + generate keys
pub fn init(
    config_path: Option<PathBuf>,
    pubkey_display: Option<PubkeyDisplay>,
    bech32_prefix: Option<String>,
    aws_region: String,
    kms_key_id: String,
) -> Result<(), String> {
    let cp = config_path.unwrap_or("tmkms.toml".into());
    let mut config = NitroSignOpt::default();
    config.aws_region = aws_region;
    let t = toml::to_string_pretty(&config)
        .map_err(|e| format!("failed to create a config in toml: {:?}", e))?;
    fs::write(cp, t).map_err(|e| format!("failed to write a config: {:?}", e))?;
    fs::create_dir_all(
        config
            .sealed_consensus_key_path
            .parent()
            .ok_or("cannot create a dir in a root directory".to_owned())?,
    )
    .map_err(|e| format!("failed to create dirs for key storage: {:?}", e))?;
    fs::create_dir_all(
        config
            .state_file_path
            .parent()
            .ok_or("cannot create a dir in a root directory".to_owned())?,
    )
    .map_err(|e| format!("failed to create dirs for state storage: {:?}", e))?;
    let pubkey = generate_key(
        config.sealed_consensus_key_path,
        &config.aws_region,
        kms_key_id.clone(),
    )
    .map_err(|e| format!("failed to generate a key: {:?}", e))?;
    print_pubkey(bech32_prefix, pubkey_display, pubkey);
    if let Some(id_path) = config.sealed_id_key_path {
        generate_key(id_path, &config.aws_region, kms_key_id)
            .map_err(|e| format!("failed to generate a key: {:?}", e))?;
    }
    Ok(())
}

/// push config to enclave, start up a proxy (if needed) + state syncer
pub fn start(config_path: Option<PathBuf>) -> Result<(), String> {
    let cp = config_path.unwrap_or("tmkms.toml".into());
    if !cp.exists() {
        Err("missing tmkms.toml file".to_owned())
    } else {
        let mut system = sysinfo::System::new_all();
        system.refresh_all();
        if system
            .get_processes()
            .iter()
            .find(|(_pid, p)| p.name() == "vsock-proxy")
            .is_none()
        {
            return Err("vsock-proxy not running".to_owned());
        }

        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::INFO)
            .finish();

        tracing::subscriber::set_global_default(subscriber)
            .map_err(|e| format!("setting default subscriber failed: {:?}", e))?;
        let toml_string = fs::read_to_string(cp).expect("toml config file read");
        let config: NitroSignOpt = toml::from_str(&toml_string).expect("configuration");
        let credentials = if let Some(credentials) = config.credentials {
            credentials.clone()
        } else {
            let mut rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            let credentials = rt
                .block_on(async move { InstanceMetadataProvider::new().credentials().await })
                .expect("credentials");
            AwsCredentials {
                aws_key_id: credentials.aws_access_key_id().to_owned(),
                aws_secret_key: credentials.aws_secret_access_key().to_owned(),
                aws_session_token: credentials
                    .token()
                    .as_ref()
                    .expect("session token")
                    .to_owned(),
            }
        };
        let peer_id = match &config.address {
            net::Address::Tcp { peer_id, .. } => peer_id.clone(),
            _ => None,
        };
        let state_syncer = StateSyncer::new(config.state_file_path, config.enclave_state_port)
            .expect("state syncer");
        let sealed_consensus_key = fs::read(config.sealed_consensus_key_path).expect("key bytes");
        let sealed_id_key = if let Some(p) = config.sealed_id_key_path {
            if let net::Address::Tcp { .. } = config.address {
                Some(fs::read(p).expect("key bytes"))
            } else {
                None
            }
        } else {
            None
        };
        let enclave_config = NitroConfig {
            chain_id: config.chain_id.clone(),
            max_height: config.max_height.clone(),
            sealed_consensus_key,
            sealed_id_key,
            peer_id,
            enclave_state_port: config.enclave_state_port,
            enclave_tendermint_conn: config.enclave_tendermint_conn,
            credentials,
            aws_region: config.aws_region,
        };
        let addr = SockAddr::new_vsock(config.enclave_config_cid, config.enclave_config_port);
        let mut socket = vsock::VsockStream::connect(&addr).expect("config stream");
        let config_raw = serde_json::to_vec(&enclave_config).expect("serialize config");
        write_u16_payload(&mut socket, &config_raw).expect("write config");
        let proxy = match &config.address {
            net::Address::Unix { path } => {
                debug!(
                    "{}: Creating a proxy {}...",
                    &config.chain_id, &config.address
                );

                Some(Proxy::new(config.enclave_tendermint_conn, path.clone()))
            }
            _ => None,
        };
        if let Some(p) = proxy {
            p.launch_proxy();
        }
        state_syncer.launch_syncer().join().expect("state syncing");
        Ok(())
    }
}
