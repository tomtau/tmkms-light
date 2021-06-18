mod command;
mod config;
mod runner;
mod shared;
mod state;
use crate::config::RecoverConfig;
use shared::SgxInitRequest;
use std::fmt::Debug;
use std::path::PathBuf;
use structopt::StructOpt;
use tmkms_light::utils::PubkeyDisplay;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "tmkms-light-sgx-runner",
    about = "runner for signing backend app using SGX"
)]
enum TmkmsLight {
    #[structopt(name = "cloud-wrap", about = "Generate a wrap key for cloud backups")]
    /// Create config + keygen
    CloudWrapKeyGen {
        #[structopt(short)]
        enclave_path: Option<PathBuf>,
        #[structopt(short)]
        sealed_wrap_key_path: Option<PathBuf>,
        #[structopt(short)]
        dcap: bool,
        /// log level, default: info, -v: info, -vv: debug, -vvv: trace
        #[structopt(short, parse(from_occurrences))]
        v: u32,
    },
    #[structopt(name = "init", about = "Create config and generate keys")]
    /// Create config + keygen
    Init {
        #[structopt(short)]
        config_path: Option<PathBuf>,
        #[structopt(short)]
        pubkey_display: Option<PubkeyDisplay>,
        #[structopt(short)]
        bech32_prefix: Option<String>,
        #[structopt(short)]
        wrap_backup_key_path: Option<PathBuf>,
        #[structopt(short)]
        external_cloud_key_path: Option<PathBuf>,
        #[structopt(short)]
        key_backup_data_path: Option<PathBuf>,
        #[structopt(short, parse(from_occurrences))]
        v: u32,
    },
    #[structopt(name = "recover", about = "Recover from cloud backup")]

    /// Recover from cloud backup payload
    Recover {
        #[structopt(flatten)]
        config: RecoverConfig,
        #[structopt(short, parse(from_occurrences))]
        v: u32,
    },
    #[structopt(name = "start", about = "Start tmkms process")]
    /// start tmkms process
    Start {
        #[structopt(short)]
        config_path: Option<PathBuf>,
        #[structopt(short, parse(from_occurrences))]
        v: u32,
    },
}

fn set_log(v: u32) -> String {
    let (log_level, log_level_str) = match v {
        0 | 1 => (Level::INFO, "info"),
        2 => (Level::DEBUG, "verbose"),
        _ => (Level::TRACE, "verbose"),
    };
    let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    log_level_str.into()
}

fn main() {
    let opt = TmkmsLight::from_args();
    let result = match opt {
        TmkmsLight::CloudWrapKeyGen {
            enclave_path,
            sealed_wrap_key_path,
            dcap,
            v,
        } => {
            let log_level_str = set_log(v);
            let enclave_path =
                enclave_path.unwrap_or_else(|| "enclave/tmkms-light-sgx-app.sgxs".into());
            let sealed_wrap_key_path =
                sealed_wrap_key_path.unwrap_or_else(|| "sealed-wrap.key".into());
            command::keywrap(enclave_path, sealed_wrap_key_path, dcap, log_level_str)
        }
        TmkmsLight::Init {
            config_path,
            pubkey_display,
            bech32_prefix,
            wrap_backup_key_path,
            external_cloud_key_path,
            key_backup_data_path,
            v,
        } => {
            let log_level_str = set_log(v);
            command::init(
                config_path,
                pubkey_display,
                bech32_prefix,
                wrap_backup_key_path,
                external_cloud_key_path,
                key_backup_data_path,
                log_level_str,
            )
        }
        TmkmsLight::Start { config_path, v } => {
            let log_level_str = set_log(v);
            command::start(config_path, log_level_str)
        }
        TmkmsLight::Recover { config, v } => {
            let log_level_str = set_log(v);
            command::recover(config, log_level_str)
        }
    };
    if let Err(e) = result {
        error!("{}", e);
        std::process::exit(1);
    }
}
