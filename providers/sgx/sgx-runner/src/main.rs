mod command;
mod config;
mod runner;
mod shared;
mod state;
use shared::{SgxInitRequest, CLOUD_KEY_LEN};
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
        external_backup_key_path: Option<PathBuf>,
        #[structopt(short)]
        key_backup_data_path: Option<PathBuf>,
    },
    #[structopt(name = "recover", about = "Recover from cloud backup")]
    /// Recover from cloud backup payload
    Recover {
        #[structopt(short)]
        config_path: Option<PathBuf>,
        #[structopt(short)]
        pubkey_display: Option<PubkeyDisplay>,
        #[structopt(short)]
        bech32_prefix: Option<String>,
        #[structopt(short)]
        external_backup_key_path: PathBuf,
        #[structopt(short)]
        key_backup_data_path: PathBuf,
        #[structopt(short)]
        recover_consensus_key: bool,
    },
    #[structopt(name = "start", about = "Start tmkms process")]
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
    let result = match opt {
        TmkmsLight::CloudWrapKeyGen {
            enclave_path,
            sealed_wrap_key_path,
            dcap,
        } => {
            let enclave_path = enclave_path.unwrap_or("enclave/tmkms-light-sgx-app.sgxs".into());
            let sealed_wrap_key_path = sealed_wrap_key_path.unwrap_or("sealed-wrap.key".into());
            command::keywrap(enclave_path, sealed_wrap_key_path, dcap)
        }
        TmkmsLight::Init {
            config_path,
            pubkey_display,
            bech32_prefix,
            external_backup_key_path,
            key_backup_data_path,
        } => command::init(
            config_path,
            pubkey_display,
            bech32_prefix,
            external_backup_key_path,
            key_backup_data_path,
        ),
        TmkmsLight::Start { config_path } => command::start(config_path),
        TmkmsLight::Recover {
            config_path,
            pubkey_display,
            bech32_prefix,
            external_backup_key_path,
            key_backup_data_path,
            recover_consensus_key,
        } => command::recover(
            config_path,
            pubkey_display,
            bech32_prefix,
            external_backup_key_path,
            key_backup_data_path,
            recover_consensus_key,
        ),
    };
    if let Err(e) = result {
        error!("{}", e);
        std::process::exit(1);
    }
}
