mod config;
mod key_utils;
mod state;
use state::StateHolder;
use std::{fmt::Debug, os::unix::net::UnixStream};
use std::{fs, path::PathBuf};
use std::{net::TcpStream, time::Duration};
use structopt::StructOpt;
use subtle::ConstantTimeEq;
use tendermint::net;
use tendermint_p2p::secret_connection::{self, PublicKey, SecretConnection};
use tmkms_light::connection::{Connection, PlainConnection};
use tmkms_light::{
    chain::state::PersistStateSync,
    config::validator::ValidatorConfig,
    utils::{print_pubkey, PubkeyDisplay},
};
use tracing::{debug, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "tmkms-softsign",
    about = "software signing for testing purposes"
)]
enum TmkmsLight {
    #[structopt(name = "init", about = "Create config + keygen")]
    /// Create config + keygen
    Init {
        #[structopt(short)]
        config_path: Option<PathBuf>,
    },
    #[structopt(name = "start", about = "start tmkms process")]
    /// start tmkms process
    Start {
        #[structopt(short)]
        config_path: Option<PathBuf>,
    },
    #[structopt(name = "pubkey", about = "display consensus public key")]
    /// displays consensus public key
    Pubkey {
        #[structopt(short)]
        config_path: Option<PathBuf>,
        #[structopt(short)]
        ptype: Option<PubkeyDisplay>,
        #[structopt(short)]
        bech32_prefix: Option<String>,
    },
}

fn main() {
    let opt = TmkmsLight::from_args();
    match opt {
        TmkmsLight::Init { config_path } => {
            let cp = config_path.unwrap_or_else(|| "tmkms.toml".into());
            let config = config::SoftSignOpt::default();
            let t = toml::to_string_pretty(&config).expect("config in toml");
            fs::write(cp, t).expect("written config");
            fs::create_dir_all(config.consensus_key_path.parent().expect("not root dir"))
                .expect("create dirs for key storage");
            key_utils::generate_key(config.consensus_key_path).expect("keygen failed");
            if let Some(id_path) = config.id_key_path {
                fs::create_dir_all(id_path.parent().expect("not root dir"))
                    .expect("create dirs for key storage");
                key_utils::generate_key(id_path).expect("keygen failed");
            }
            fs::create_dir_all(config.state_file_path.parent().expect("not root dir"))
                .expect("create dirs for key storage");
        }
        TmkmsLight::Start { config_path } => {
            let cp = config_path.unwrap_or_else(|| "tmkms.toml".into());
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
                let config: config::SoftSignOpt =
                    toml::from_str(&toml_string).expect("configuration");
                let mut state_holder = StateHolder::new(config.state_file_path);
                let state = state_holder.load_state().expect("state loaded");
                let keypair = key_utils::load_base64_ed25519_key(config.consensus_key_path)
                    .expect("secret keypair");
                let connection: Box<dyn Connection> = match &config.address {
                    net::Address::Tcp {
                        peer_id,
                        host,
                        port,
                    } => {
                        debug!(
                            "[{}@{}] connecting to validator...",
                            &config.chain_id, &config.address
                        );
                        /// Default timeout in seconds
                        const DEFAULT_TIMEOUT: u16 = 10;

                        let identity_key_path = config.id_key_path.as_ref().unwrap_or_else(|| {
                            panic!(
                                "config error: no `secret_key` for validator: {}:{}",
                                host, port
                            )
                        });

                        let identity_key = key_utils::load_base64_ed25519_key(identity_key_path)
                            .expect("id keypair");
                        info!("KMS node ID: {}", PublicKey::from(&identity_key));
                        let mut msocket;
                        loop {
                            msocket = TcpStream::connect(format!("{}:{}", host, port)).ok();
                            if msocket.is_some() || !config.retry {
                                break;
                            }
                        }
                        let socket = msocket.expect("tcp connection");
                        let timeout =
                            Duration::from_secs(config.timeout.unwrap_or(DEFAULT_TIMEOUT).into());
                        socket
                            .set_read_timeout(Some(timeout))
                            .expect("read timeout set");
                        socket
                            .set_write_timeout(Some(timeout))
                            .expect("write timeout set");

                        let connection = SecretConnection::new(
                            socket,
                            identity_key,
                            secret_connection::Version::V0_34,
                        )
                        .expect("secret connection");
                        let actual_peer_id = connection.remote_pubkey().peer_id();

                        // TODO: https://github.com/informalsystems/tendermint-rs/issues/786
                        if let Some(expected_peer_id) = peer_id {
                            if expected_peer_id.ct_eq(&actual_peer_id).unwrap_u8() == 0 {
                                panic!(
                                    "{}:{}: validator peer ID mismatch! (expected {}, got {})",
                                    host, port, expected_peer_id, actual_peer_id
                                );
                            }
                        }
                        info!(
                            "[{}@{}] connected to validator successfully",
                            &config.chain_id, &config.address
                        );

                        if peer_id.is_none() {
                            // TODO: https://github.com/informalsystems/tendermint-rs/issues/786
                            warn!(
                                "[{}@{}]: unverified validator peer ID! ({})",
                                &config.chain_id,
                                &config.address,
                                connection.remote_pubkey().peer_id()
                            );
                        }

                        Box::new(connection)
                    }
                    net::Address::Unix { path } => {
                        if let Some(timeout) = config.timeout {
                            warn!("timeouts not supported with Unix sockets: {}", timeout);
                        }

                        debug!(
                            "{}: Connecting to socket at {}...",
                            &config.chain_id, &config.address
                        );
                        let mut msocket;
                        loop {
                            msocket = UnixStream::connect(path).ok();
                            if msocket.is_some() || !config.retry {
                                break;
                            }
                        }
                        let socket = msocket.expect("unix socket open");
                        let conn = PlainConnection::new(socket);

                        info!(
                            "[{}@{}] connected to validator successfully",
                            &config.chain_id, &config.address
                        );

                        Box::new(conn)
                    }
                };
                let mut session = tmkms_light::session::Session::new(
                    ValidatorConfig {
                        chain_id: config.chain_id,
                        max_height: config.max_height,
                    },
                    connection,
                    keypair,
                    state,
                    state_holder,
                );
                session.request_loop().expect("request loop");
            }
        }
        TmkmsLight::Pubkey {
            config_path,
            ptype,
            bech32_prefix,
        } => {
            let cp = config_path.unwrap_or_else(|| "tmkms.toml".into());
            if !cp.exists() {
                eprintln!("missing tmkms.toml file");
                std::process::exit(1);
            } else {
                let toml_string = fs::read_to_string(cp).expect("toml config file read");
                let config: config::SoftSignOpt =
                    toml::from_str(&toml_string).expect("configuration");
                let keypair = key_utils::load_base64_ed25519_key(config.consensus_key_path)
                    .expect("secret keypair");
                print_pubkey(bech32_prefix, ptype, keypair.public);
            }
        }
    }
}
