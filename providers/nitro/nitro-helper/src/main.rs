mod config;
mod key_utils;
mod proxy;
mod shared;
mod state;

use nix::sys::socket::SockAddr;
use proxy::Proxy;
use rusoto_credential::{InstanceMetadataProvider, ProvideAwsCredentials};
use shared::{AwsCredentials, NitroConfig};
use state::StateSyncer;
use std::{fmt::Debug, os::unix::net::UnixStream};
use std::{fs, path::PathBuf};
use structopt::StructOpt;
use subtle_encoding::base64;
use sysinfo::{ProcessExt, SystemExt};
use tendermint::net;
use tmkms_light::{
    config::validator::ValidatorConfig,
    utils::{print_pubkey, PubkeyDisplay},
};
use tracing::{debug, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "tmkms-nitro-helper",
    about = "helper (proxies etc.) for nitro enclave execution"
)]
enum TmkmsLight {
    #[structopt(name = "init", about = "Create config + keygen")]
    /// Create config + keygen
    Init {
        #[structopt(short)]
        config_path: Option<PathBuf>,
        #[structopt(short)]
        pubkey_display: Option<PubkeyDisplay>,
        #[structopt(short)]
        bech32_prefix: Option<String>,
        #[structopt(short)]
        aws_region: String,
        #[structopt(short)]
        kms_key_id: String,
    },
    #[structopt(name = "start", about = "start tmkms process")]
    /// start tmkms process
    Start {
        #[structopt(short)]
        config_path: Option<PathBuf>,
    },
}

fn main() {
    let opt = TmkmsLight::from_args();
    match opt {
        TmkmsLight::Init {
            config_path,
            pubkey_display,
            bech32_prefix,
            aws_region,
            kms_key_id,
        } => {
            let cp = config_path.unwrap_or("tmkms.toml".into());
            let mut config = config::NitroSignOpt::default();
            config.aws_region = aws_region;
            let t = toml::to_string_pretty(&config).expect("config in toml");
            fs::write(cp, t).expect("written config");
            fs::create_dir_all(
                config
                    .sealed_consensus_key_path
                    .parent()
                    .expect("not root dir"),
            )
            .expect("create dirs for key storage");
            fs::create_dir_all(config.state_file_path.parent().expect("not root dir"))
                .expect("create dirs for key storage");
            let pubkey = key_utils::generate_key(
                config.sealed_consensus_key_path,
                &config.aws_region,
                kms_key_id.clone(),
            )
            .expect("generated key");
            print_pubkey(bech32_prefix, pubkey_display, pubkey);
            if let Some(id_path) = config.sealed_id_key_path {
                key_utils::generate_key(id_path, &config.aws_region, kms_key_id)
                    .expect("generated id key");
            }
        }
        TmkmsLight::Start { config_path } => {
            let cp = config_path.unwrap_or("tmkms.toml".into());
            if !cp.exists() {
                eprintln!("missing tmkms.toml file");
                std::process::exit(1);
            } else {
                let mut system = sysinfo::System::new_all();
                system.refresh_all();
                if system
                    .get_processes()
                    .iter()
                    .find(|(pid, p)| p.name() == "vsock-proxy")
                    .is_none()
                {
                    eprintln!("vsock-proxy not running");
                    std::process::exit(1);
                }

                let subscriber = FmtSubscriber::builder()
                    .with_max_level(Level::INFO)
                    .finish();

                tracing::subscriber::set_global_default(subscriber)
                    .expect("setting default subscriber failed");
                let toml_string = fs::read_to_string(cp).expect("toml config file read");
                let config: config::NitroSignOpt =
                    toml::from_str(&toml_string).expect("configuration");
                let credentials = if let Some(credentials) = config.credentials {
                    credentials.clone()
                } else {
                    let mut rt = tokio::runtime::Runtime::new().expect("tokio runtime");
                    let credentials = rt
                        .block_on(
                            async move { InstanceMetadataProvider::new().credentials().await },
                        )
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
                let peer_id = match &config.address {
                    net::Address::Tcp { peer_id, .. } => peer_id.clone(),
                    _ => None,
                };
                let state_syncer =
                    StateSyncer::new(config.state_file_path, config.enclave_state_port)
                        .expect("state syncer");
                let sealed_consensus_key = base64::decode(
                    fs::read_to_string(config.sealed_consensus_key_path).expect("key bytes"),
                )
                .expect("key data");
                let sealed_id_key = if let Some(p) = config.sealed_id_key_path {
                    Some(
                        base64::decode(fs::read_to_string(p).expect("key bytes"))
                            .expect("key data"),
                    )
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
                let addr =
                    SockAddr::new_vsock(config.enclave_config_cid, config.enclave_config_port);
                let mut socket = vsock::VsockStream::connect(&addr).expect("config stream");
                bincode::serialize_into(&mut socket, &enclave_config);
                if let Some(p) = proxy {
                    p.launch_proxy();
                }
                state_syncer.launch_syncer().join().expect("state syncing");
            }
        }
    }
}
