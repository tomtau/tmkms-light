mod command;
mod config;
mod enclave_log_server;
mod key_utils;
mod proxy;
mod shared;
mod state;

use command::launch_all::launch_all;
use command::nitro_enclave::{describe_enclave, run_enclave, stop_enclave};
use command::{check_vsock_proxy, init, start};
use config::{EnclaveOpt, VSockProxyOpt};

use crate::command::nitro_enclave::run_vsock_proxy;
use crate::config::{EnclaveConfig, NitroSignOpt};
use clap::Parser;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use tmkms_light::utils::PubkeyDisplay;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

/// Helper sub-commands
#[derive(Debug, Parser)]
#[command(
    name = "tmkms-nitro-helper",
    about = "helper (proxies etc.) for nitro enclave execution"
)]
enum TmkmsLight {
    #[command(flatten)]
    Helper(CommandHelper),
    #[command(subcommand)]
    Enclave(CommandEnclave),
}

/// enclave sub-commands
#[derive(Debug, Parser)]
enum CommandEnclave {
    #[command(name = "info", about = "get tmkms info")]
    Info,
    #[command(name = "run", about = "run enclave")]
    RunEnclave {
        #[command(flatten)]
        opt: EnclaveOpt,
        /// log level, default: info, -v: info, -vv: debug, -vvv: trace
        #[arg(short, action = clap::ArgAction::Count)]
        v: u32,
    },
    #[command(name = "stop", about = "stop enclave")]
    StopEnclave {
        /// Stop the enclave cid
        #[arg(long)]
        cid: Option<String>,
    },
    #[command(name = "vsock-proxy", about = "launch vsock proxy")]
    RunProxy {
        #[command(flatten)]
        opt: VSockProxyOpt,
        /// log level, default: info, -v: info, -vv: debug, -vvv: trace
        #[arg(short, action = clap::ArgAction::Count)]
        v: u32,
    },
}

/// Helper sub-commands
#[derive(Debug, Parser)]
enum CommandHelper {
    #[command(name = "init", about = "Create config + keygen")]
    /// Create config + keygen
    Init {
        /// the directory put the generated config files
        #[arg(short, default_value = "./")]
        config_dir: PathBuf,
        #[arg(short)]
        pubkey_display: Option<PubkeyDisplay>,
        #[arg(short)]
        bech32_prefix: Option<String>,
        #[arg(short)]
        aws_region: String,
        #[arg(short)]
        kms_key_id: String,
        #[arg(long)]
        cid: Option<u32>,
    },
    #[command(name = "start", about = "start tmkms process")]
    /// start tmkms process (push config + start up proxy and state persistence)
    Start {
        #[arg(short, default_value = "tmkms.toml")]
        config_path: PathBuf,
        #[arg(long)]
        cid: Option<u32>,
        /// log level, default: info, -v: info, -vv: debug, -vvv: trace
        #[arg(short, action = clap::ArgAction::Count)]
        v: u32,
    },
    #[command(name = "launch-all", about = "launch all")]
    LaunchAll {
        /// tmkms config path
        #[arg(short, default_value = "tmkms.toml")]
        tmkms_config: PathBuf,
        /// enclave config path
        #[arg(short, default_value = "enclave.toml")]
        enclave_config: PathBuf,
        /// log level, default: info, -v: info, -vv: debug, -vvv: trace
        #[arg(short, action = clap::ArgAction::Count)]
        v: u32,
    },
}

fn set_logger(v: u32) -> Result<(), String> {
    let log_level = match v {
        0 | 1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };
    let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| format!("setting default subscriber failed: {:?}", e))?;
    Ok(())
}

fn run() -> Result<(), String> {
    let opt = TmkmsLight::parse();
    match opt {
        TmkmsLight::Helper(CommandHelper::Init {
            config_dir,
            pubkey_display,
            bech32_prefix,
            aws_region,
            kms_key_id,
            cid,
        }) => {
            init(
                config_dir,
                pubkey_display,
                bech32_prefix,
                aws_region,
                kms_key_id,
                cid,
            )?;
        }
        TmkmsLight::Helper(CommandHelper::Start {
            config_path,
            cid,
            v,
        }) => {
            set_logger(v)?;
            let config = NitroSignOpt::from_file(config_path)?;
            if !check_vsock_proxy() {
                return Err("vsock proxy not started".to_string());
            }
            let (sender, receiver) = channel();
            ctrlc::set_handler(move || {
                let _ = sender.send(());
            })
            .map_err(|_| "Error to set Ctrl-C channel".to_string())?;
            start(&config, cid, receiver)?;
        }
        TmkmsLight::Enclave(CommandEnclave::Info) => {
            let info = describe_enclave()?;
            let s = serde_json::to_string_pretty(&info)
                .map_err(|_| "get invalid enclave info".to_string())?;
            println!("enclave status:\n{}", s);
        }
        TmkmsLight::Enclave(CommandEnclave::RunEnclave { opt, v }) => {
            set_logger(v)?;
            let (sender, receiver) = channel();
            ctrlc::set_handler(move || {
                let _ = sender.send(());
            })
            .map_err(|_| "Error to set Ctrl-C channel".to_string())?;
            run_enclave(&opt, receiver)?;
        }
        TmkmsLight::Enclave(CommandEnclave::StopEnclave { cid }) => {
            stop_enclave(cid)?;
        }
        TmkmsLight::Enclave(CommandEnclave::RunProxy { opt, v }) => {
            set_logger(v)?;
            let (sender, receiver) = channel();
            ctrlc::set_handler(move || {
                let _ = sender.send(());
            })
            .map_err(|_| "Error to set Ctrl-C channel".to_string())?;
            run_vsock_proxy(&opt, receiver)?;
        }
        TmkmsLight::Helper(CommandHelper::LaunchAll {
            tmkms_config,
            enclave_config,
            v,
        }) => {
            set_logger(v)?;
            let tmkms_config = NitroSignOpt::from_file(tmkms_config)?;
            let enclave_config = EnclaveConfig::from_file(enclave_config)?;
            launch_all(tmkms_config, enclave_config)?;
        }
    };
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
