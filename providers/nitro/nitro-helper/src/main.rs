mod command;
mod config;
mod enclave_log_server;
mod key_utils;
mod proxy;
mod shared;
mod state;

use std::path::PathBuf;
use structopt::StructOpt;
use tmkms_light::utils::PubkeyDisplay;
use tracing::Level;

/// Helper sub-commands
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
        #[structopt(long)]
        cid: Option<u32>,
    },
    #[structopt(name = "start", about = "start tmkms process")]
    /// start tmkms process (push config + start up proxy and state persistence)
    Start {
        #[structopt(short)]
        config_path: Option<PathBuf>,
        #[structopt(long)]
        cid: Option<u32>,
        #[structopt(short, parse(from_occurrences))]
        /// log level, default: info, -v: info, -vv: debug, -vvv: trace
        #[structopt(short, parse(from_occurrences))]
        v: u32,
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
            cid,
        } => command::init(
            config_path,
            pubkey_display,
            bech32_prefix,
            aws_region,
            kms_key_id,
            cid,
        ),
        TmkmsLight::Start {
            config_path,
            cid,
            v,
        } => {
            let log_level = match v {
                0 | 1 => Level::INFO,
                2 => Level::DEBUG,
                _ => Level::TRACE,
            };
            command::start(config_path, cid, log_level)
        }
    };
    if let Err(e) = result {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
