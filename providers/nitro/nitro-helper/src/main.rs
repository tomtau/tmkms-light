mod command;
mod config;
mod key_utils;
mod proxy;
mod shared;
mod state;

use std::path::PathBuf;
use structopt::StructOpt;
use tmkms_light::utils::PubkeyDisplay;
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
    let result = match opt {
        TmkmsLight::Init {
            config_path,
            pubkey_display,
            bech32_prefix,
            aws_region,
            kms_key_id,
        } => command::init(
            config_path,
            pubkey_display,
            bech32_prefix,
            aws_region,
            kms_key_id,
        ),
        TmkmsLight::Start { config_path } => command::start(config_path),
    };
    if let Err(e) = result {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
