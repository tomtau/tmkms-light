mod config;
mod key_utils;
mod proxy;
mod state;

use std::{fmt::Debug, os::unix::net::UnixStream};
use std::{fs, path::PathBuf};
use structopt::StructOpt;
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
                todo!()
            }
        }
    }
}
