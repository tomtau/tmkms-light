/// state persistence helper;
mod state;

use anomaly::format_err;
use ed25519_dalek as ed25519;
use nix::sys::socket::SockAddr;
use std::io;
use std::os::unix::io::AsRawFd;
use subtle::ConstantTimeEq;
use tendermint::node::Id;
use tendermint_p2p::secret_connection::{self, PublicKey, SecretConnection};
use tmkms_light::chain::state::PersistStateSync;
use tmkms_light::config::validator::ValidatorConfig;
use tmkms_light::connection::{Connection, PlainConnection};
use tmkms_light::error::{
    Error,
    ErrorKind::{AccessError, InvalidKey, IoError},
};
use tmkms_light::utils::read_u16_payload;
use tmkms_nitro_helper::{NitroConfig, VSOCK_PROXY_CID};
use tracing::{error, info, trace, warn};
use vsock::VsockStream;
use zeroize::Zeroizing;

fn get_secret_connection(
    vsock_port: u32,
    identity_key: ed25519::Keypair,
    peer_id: Option<Id>,
) -> io::Result<Box<dyn Connection>> {
    let addr = SockAddr::new_vsock(VSOCK_PROXY_CID, vsock_port);
    let socket = vsock::VsockStream::connect(&addr)?;
    info!("KMS node ID: {}", PublicKey::from(&identity_key));

    let connection =
        SecretConnection::new(socket, &identity_key, secret_connection::Version::V0_34).map_err(
            |e| {
                error!("secret connection failed: {}", e);
                io::Error::from(io::ErrorKind::Other)
            },
        )?;
    let actual_peer_id = connection.remote_pubkey().peer_id();

    // TODO(tarcieri): move this into `SecretConnection::new`
    if let Some(expected_peer_id) = peer_id {
        if expected_peer_id.ct_eq(&actual_peer_id).unwrap_u8() == 0 {
            error!(
                "(vsock port {}): validator peer ID mismatch! (expected {}, got {})",
                vsock_port, expected_peer_id, actual_peer_id
            );
            return Err(io::Error::from(io::ErrorKind::Other));
        }
    }
    info!("connected to validator successfully");

    if peer_id.is_none() {
        // TODO(tarcieri): make peer verification mandatory
        warn!(
            "unverified validator peer ID! ({})",
            connection.remote_pubkey().peer_id()
        );
    }

    Ok(Box::new(connection))
}

/// a simple req-rep handling loop
pub fn entry(mut config_stream: VsockStream) -> Result<(), Error> {
    let json_raw = read_u16_payload(&mut config_stream)
        .map_err(|_e| format_err!(IoError, "failed to read config"))?;
    let mconfig = serde_json::from_slice(&json_raw);
    match mconfig {
        Ok(config) => {
            let config: NitroConfig = config;
            let key_bytes = Zeroizing::new(
                aws_ne_sys::kms_decrypt(
                    config.aws_region.as_bytes(),
                    config.credentials.aws_key_id.as_bytes(),
                    config.credentials.aws_secret_key.as_bytes(),
                    config.credentials.aws_session_token.as_bytes(),
                    config.sealed_consensus_key.as_ref(),
                )
                .map_err(|_e| format_err!(AccessError, "failed to decrypt key"))?,
            );
            loop {
                let mut state_holder = state::StateHolder::new(config.enclave_state_port)
                    .map_err(|_e| format_err!(IoError, "failed get state connection"))?;
                if let Ok(state) = state_holder.load_state() {
                    let secret = ed25519::SecretKey::from_bytes(&*key_bytes)
                        .map_err(|e| format_err!(InvalidKey, "invalid Ed25519 key: {}", e))?;
                    let public = ed25519::PublicKey::from(&secret);
                    let keypair = ed25519::Keypair { secret, public };

                    let conn: Box<dyn Connection> = if let Some(ref ciphertext) =
                        config.sealed_id_key
                    {
                        let id_key_bytes = Zeroizing::new(
                            aws_ne_sys::kms_decrypt(
                                config.aws_region.as_bytes(),
                                config.credentials.aws_key_id.as_bytes(),
                                config.credentials.aws_secret_key.as_bytes(),
                                config.credentials.aws_session_token.as_bytes(),
                                ciphertext.as_ref(),
                            )
                            .map_err(|_e| format_err!(AccessError, "failed to decrypt key"))?,
                        );
                        let id_secret = ed25519::SecretKey::from_bytes(&*id_key_bytes)
                            .map_err(|e| format_err!(InvalidKey, "invalid Ed25519 key: {}", e))?;
                        let id_public = ed25519::PublicKey::from(&id_secret);
                        let id_keypair = ed25519::Keypair {
                            secret: id_secret,
                            public: id_public,
                        };
                        get_secret_connection(
                            config.enclave_tendermint_conn,
                            id_keypair,
                            config.peer_id,
                        )
                        .map_err(|_e| format_err!(IoError, "failed get tendermint connection"))?
                    } else {
                        let addr =
                            SockAddr::new_vsock(VSOCK_PROXY_CID, config.enclave_tendermint_conn);
                        let socket = vsock::VsockStream::connect(&addr)
                            .map_err(|_e| format_err!(IoError, "failed get privval connection"))?;
                        trace!("tendermint vsock port: {}", config.enclave_tendermint_conn);
                        trace!("tendermint peer addr: {:?}", socket.peer_addr());
                        trace!("tendermint local addr: {:?}", socket.local_addr());
                        trace!("tendermint fd: {}", socket.as_raw_fd());
                        info!("connected to validator successfully");
                        let plain_conn = PlainConnection::new(socket);
                        Box::new(plain_conn)
                    };
                    let mut session = tmkms_light::session::Session::new(
                        ValidatorConfig {
                            chain_id: config.chain_id.clone(),
                            max_height: config.max_height,
                        },
                        conn,
                        keypair,
                        state,
                        state_holder,
                    );
                    if let Err(e) = session.request_loop() {
                        error!("request error: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            error!("config error: {}", e);
        }
    }

    Ok(())
}
