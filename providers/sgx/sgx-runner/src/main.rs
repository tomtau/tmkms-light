mod config;
mod runner;
mod shared;
mod state;
use runner::TmkmsSgxSigner;
use std::{fmt::Debug, os::unix::net::UnixStream, str::FromStr};
use std::{fs, path::PathBuf};
use structopt::StructOpt;
use tendermint::net;
use tmkms_light::config::validator::ValidatorConfig;
use tracing::{debug, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Debug)]
enum PubkeyDisplay {
    Base64,
    Bech32,
}

impl FromStr for PubkeyDisplay {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "base64" => Ok(PubkeyDisplay::Base64),
            "bech32" => Ok(PubkeyDisplay::Bech32),
            _ => Err("unknown display type".to_owned()),
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "tmkms-light-sgx-runner",
    about = "runner for signing backend app using SGX"
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
        } => {
            let cp = config_path.unwrap_or("tmkms.toml".into());
            let config = config::SgxSignOpt::default();
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
            let runner = TmkmsSgxSigner::launch_enclave_app(
                &config.enclave_path,
                None,
                &config.state_file_path,
            )
            .expect("runner");
            let sealed_key = runner.keygen().expect("gen key");
            config::write_sealed_file(config.sealed_consensus_key_path, &sealed_key)
                .expect("write key");
            match pubkey_display {
                Some(PubkeyDisplay::Bech32) => {
                    let prefix = bech32_prefix.unwrap_or("cosmosvalconspub".to_owned());
                    let mut data = vec![0x16, 0x24, 0xDE, 0x64, 0x20];
                    data.extend_from_slice(&sealed_key.seal_key_request.keyid);
                    println!(
                        "public key: {}",
                        subtle_encoding::bech32::encode(prefix, data)
                    );
                }
                _ => {
                    println!(
                        "public key: {}",
                        String::from_utf8(subtle_encoding::base64::encode(
                            sealed_key.seal_key_request.keyid
                        ))
                        .unwrap()
                    );
                    let id = tendermint::node::Id::from(
                        tendermint::public_key::Ed25519::from_bytes(
                            &sealed_key.seal_key_request.keyid,
                        )
                        .expect("tm pubkey"),
                    );
                    println!("address: {}", id);
                }
            }
            if let Some(id_path) = config.sealed_id_key_path {
                let runner = TmkmsSgxSigner::launch_enclave_app(
                    &config.enclave_path,
                    None,
                    &config.state_file_path,
                )
                .expect("runner");
                let sealed_key = runner.keygen().expect("gen key");
                config::write_sealed_file(id_path, &sealed_key).expect("write key");
            }
        }
        TmkmsLight::Start { config_path } => {
            let cp = config_path.unwrap_or("tmkms.toml".into());
            if !cp.exists() {
                eprintln!("missing tmkms.toml file");
                std::process::exit(1);
            } else {
                let subscriber = FmtSubscriber::builder()
                    .with_max_level(Level::INFO)
                    .finish();

                tracing::subscriber::set_global_default(subscriber)
                    .expect("setting default subscriber failed");
                let toml_string = fs::read_to_string(cp).expect("toml config file read");
                let config: config::SgxSignOpt =
                    toml::from_str(&toml_string).expect("configuration");
                let tm_conn = match &config.address {
                    net::Address::Unix { path } => {
                        debug!(
                            "{}: Connecting to socket at {}...",
                            &config.chain_id, &config.address
                        );

                        let socket = UnixStream::connect(path).expect("unix socket open");
                        Some(socket)
                    }
                    _ => None,
                };
                let remote = if let (None, Some(path)) = (&tm_conn, config.sealed_id_key_path) {
                    Some((config.address, path))
                } else {
                    None
                };
                let runner = TmkmsSgxSigner::launch_enclave_app(
                    &config.enclave_path,
                    tm_conn,
                    &config.state_file_path,
                )
                .expect("runner");
                runner
                    .start(
                        config.sealed_consensus_key_path,
                        ValidatorConfig {
                            chain_id: config.chain_id,
                            max_height: config.max_height,
                        },
                        remote,
                    )
                    .expect("request loop");
            }
        }
    }
}
