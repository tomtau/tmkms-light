/// state persistence helper;
mod state;

use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use std::io;
use std::net::TcpStream;
use subtle::ConstantTimeEq;
use tendermint_p2p::secret_connection::{self, PublicKey, SecretConnection};
use tmkms_light::chain::state::PersistStateSync;
use tmkms_light::connection::{Connection, PlainConnection};
use tmkms_nitro_helper::{NitroConfig, VSOCK_PROXY_CID};
use tracing::{error, info, warn};
use vsock::VsockStream;
use zeroize::Zeroizing;

fn get_secret_connection(
    vsock_port: u32,
    identity_key: ed25519_dalek::SecretKey,
    peer_id: Option<Id>,
) -> io::Result<Box<dyn Connection>> {
    let addr = vsock::SockAddr::new_vsock(VSOCK_PROXY_CID, vsock_port);
    let mut socket = vsock::VsockStream::connect(&addr)?;
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
                "{}:{}: validator peer ID mismatch! (expected {}, got {})",
                host, port, expected_peer_id, actual_peer_id
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
pub fn entry(mut config_stream: VsockStream) {
    let mut csprng = OsRng {};
    let mconfig: bincode::Result<NitroConfig> = bincode::deserialize_from(&mut config_stream);
    match mconfig {
        Ok(config) => {
            let key_bytes = //Zeroizing::new(
                aws_ne_sys::kms_decrypt(config.aws_region.as_bytes(),
                config.credentials.aws_key_id.as_bytes(),
                config.credentials.aws_secret_key.as_bytes(),
                config.credentials.aws_session_token.as_bytes(),
                config.sealed_consensus_key.as_ref());
            // );
            todo!()
        }
        Err(e) => {
            error!("config error: {}", e);
        }
    }

    Ok(())
}
