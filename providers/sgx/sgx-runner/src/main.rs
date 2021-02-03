mod config;
mod runner;
mod shared;
mod state;
use runner::TmkmsSgxSigner;
use std::{fmt::Debug, thread, time::Duration};
use std::{fs, path::PathBuf};
use structopt::StructOpt;
use tendermint::net;
use tmkms_light::{
    config::validator::ValidatorConfig,
    utils::{print_pubkey, PubkeyDisplay},
};
use tmkms_light_sgx_runner::{SgxInitRequest, CLOUD_KEY_LEN};
use tracing::{debug, Level};
use tracing_subscriber::FmtSubscriber;
use zeroize::Zeroizing;

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
        #[structopt(short)]
        backup_key_path: Option<PathBuf>,
    },
    #[structopt(name = "recover", about = "Create config + keygen")]
    /// Recover from cloud backup payload
    Recover {
        #[structopt(short)]
        config_path: Option<PathBuf>,
        #[structopt(short)]
        pubkey_display: Option<PubkeyDisplay>,
        #[structopt(short)]
        bech32_prefix: Option<String>,
        #[structopt(short)]
        backup_key_path: PathBuf,
        #[structopt(short)]
        backup_data_path: PathBuf,
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
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    match opt {
        TmkmsLight::Init {
            config_path,
            pubkey_display,
            bech32_prefix,
            backup_key_path,
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
            let request = SgxInitRequest::KeyGen;
            let request_bytes = serde_json::to_vec(&request).expect("serde");
            let backup_key = if let Some(bkp) = backup_key_path {
                let key_bytes = Zeroizing::new(fs::read(bkp).expect("key"));
                if key_bytes.len() != CLOUD_KEY_LEN {
                    eprintln!("incorrect backup key length");
                    std::process::exit(1);
                }
                Some(Zeroizing::new(subtle_encoding::hex::encode(&*key_bytes)))
            } else {
                None
            };
            debug!("launching enclave");
            let (state_syncer, _, state_stream) =
                TmkmsSgxSigner::get_state_syncer(&config.state_file_path);
            let mut enclave_args: Vec<&[u8]> = vec![request_bytes.as_ref()];
            if let Some(ref bkp) = backup_key {
                enclave_args.push(&*bkp);
            }
            let runner = TmkmsSgxSigner::launch_enclave_app(
                &config.enclave_path,
                None,
                state_syncer,
                state_stream,
                &enclave_args,
            )
            .expect("runner");
            debug!("waiting for keygen");
            let sealed_key = runner.keygen().expect("gen key");
            config::write_sealed_file(config.sealed_consensus_key_path, &sealed_key.0)
                .expect("write key");
            let public_key =
                ed25519_dalek::PublicKey::from_bytes(&sealed_key.0.seal_key_request.keyid)
                    .expect("valid public key");
            print_pubkey(bech32_prefix, pubkey_display, public_key);
            if let Some(bkp) = sealed_key.1 {
                println!(
                    "consensus key cloud backup: {}",
                    serde_json::to_string_pretty(&bkp).expect("serde")
                );
            }
            if let Some(id_path) = config.sealed_id_key_path {
                let (state_syncer, _, state_stream) =
                    TmkmsSgxSigner::get_state_syncer(&config.state_file_path);

                let runner = TmkmsSgxSigner::launch_enclave_app(
                    &config.enclave_path,
                    None,
                    state_syncer,
                    state_stream,
                    &enclave_args,
                )
                .expect("runner");
                let sealed_key = runner.keygen().expect("gen key");
                config::write_sealed_file(id_path, &sealed_key.0).expect("write key");
                if let Some(bkp) = sealed_key.1 {
                    println!(
                        "id key cloud backup: {}",
                        serde_json::to_string_pretty(&bkp).expect("serde")
                    );
                }
            }
        }
        TmkmsLight::Start { config_path } => {
            let cp = config_path.unwrap_or("tmkms.toml".into());
            if !cp.exists() {
                eprintln!("missing tmkms.toml file");
                std::process::exit(1);
            } else {
                let toml_string = fs::read_to_string(cp).expect("toml config file read");
                let config: config::SgxSignOpt =
                    toml::from_str(&toml_string).expect("configuration");
                let tm_conn = match &config.address {
                    net::Address::Unix { path } => {
                        debug!(
                            "{}: Connecting to socket at {}...",
                            &config.chain_id, &config.address
                        );

                        Some(path.clone())
                    }
                    _ => None,
                };
                let remote = if let (None, Some(path)) = (&tm_conn, config.sealed_id_key_path) {
                    Some((config.address, path))
                } else {
                    None
                };
                let (state_syncer, state, state_stream) =
                    TmkmsSgxSigner::get_state_syncer(&config.state_file_path);
                let start_request_bytes = TmkmsSgxSigner::get_start_request_bytes(
                    config.sealed_consensus_key_path,
                    ValidatorConfig {
                        chain_id: config.chain_id,
                        max_height: config.max_height,
                    },
                    state,
                    remote,
                )
                .expect("start");
                let runner = TmkmsSgxSigner::launch_enclave_app(
                    &config.enclave_path,
                    tm_conn,
                    state_syncer,
                    state_stream,
                    &[&start_request_bytes],
                )
                .expect("runner");
                runner.start().expect("request loop");
            }
        }
        TmkmsLight::Recover {
            config_path,
            pubkey_display,
            bech32_prefix,
            backup_key_path,
            backup_data_path,
        } => {}
    }
}
