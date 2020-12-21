mod config;
mod runner;
mod shared;
mod state;
use runner::TmkmsSgxSigner;
use std::{fmt::Debug, os::unix::net::UnixStream, str::FromStr};
use std::{fs, path::PathBuf};
use structopt::StructOpt;
use tracing::{debug, info, warn, Level};
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
                todo!()
            }
        }
    }
}
