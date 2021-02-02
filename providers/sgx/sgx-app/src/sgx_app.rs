/// helpers for keypair sealing/unsealing
mod keypair_seal;
/// state persistence helper;
mod state;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tendermint_p2p::secret_connection::{self, PublicKey, SecretConnection};
use tmkms_light::chain::state::PersistStateSync;
use tmkms_light::connection::{Connection, PlainConnection};
use tmkms_light::utils::{read_u16_payload, write_u16_payload};
use tmkms_light_sgx_runner::RemoteConnectionConfig;
use tmkms_light_sgx_runner::{SgxInitRequest, SgxInitResponse};
use tracing::{debug, error, info, warn};

fn get_secret_connection(config: &RemoteConnectionConfig) -> io::Result<Box<dyn Connection>> {
    let RemoteConnectionConfig {
        peer_id,
        host,
        port,
        sealed_key,
    } = config;
    let socket = TcpStream::connect(format!("{}:{}", host, port))?;
    if let Ok(identity_key) = keypair_seal::unseal(&sealed_key) {
        info!("KMS node ID: {}", PublicKey::from(&identity_key));

        let connection =
            SecretConnection::new(socket, &identity_key, secret_connection::Version::V0_34)
                .map_err(|e| {
                    error!("secret connection failed: {}", e);
                    io::Error::from(io::ErrorKind::Other)
                })?;
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
    } else {
        error!("unsealing failed");
        Err(io::ErrorKind::Other.into())
    }
}

pub fn get_connection(secret_connection: Option<&RemoteConnectionConfig>) -> Box<dyn Connection> {
    loop {
        let conn: io::Result<Box<dyn Connection>> = if let Some(config) = secret_connection {
            get_secret_connection(config)
        } else {
            TcpStream::connect("tendermint").map(|socket| {
                let plain_conn = PlainConnection::new(socket);
                Box::new(plain_conn) as Box<dyn Connection>
            })
        };
        if let Err(e) = conn {
            error!("tendermint connection error {:?}", e);
            thread::sleep(Duration::new(1, 0));
        } else {
            return conn.unwrap();
        }
    }
}

/// a simple req-rep handling loop
/// `TcpStream` is either provided in tests or from the "signatory-sgx"
/// enclave runner's user call extension.
pub fn entry(mut signatory_signer: TcpStream, command: String) -> io::Result<()> {
    let mut csprng = OsRng {};
    debug!("reading request");
    let request = serde_json::from_str(&command);

    match request {
        Ok(SgxInitRequest::KeyGen {
            cloud_backup_key: _,
        }) => {
            let kp = Keypair::generate(&mut csprng);
            if let Ok(sealed_key_data) = keypair_seal::seal(&mut csprng, &kp) {
                let response = SgxInitResponse {
                    sealed_key_data,
                    cloud_backup_key_data: None, // TODO
                };
                match serde_json::to_vec(&response) {
                    Ok(v) => {
                        debug!("writing response");
                        write_u16_payload(&mut signatory_signer, &v)?;
                    }
                    Err(e) => {
                        error!("keygen error: {}", e);
                    }
                }
            } else {
                error!("sealing failed");
            }
        }
        Ok(SgxInitRequest::CloudRecover {
            key_data: _,
        }) => {
            // TODO
        }
        Ok(SgxInitRequest::Start {
            sealed_key,
            config,
            secret_connection,
            initial_state,
        }) => {
            let mut state_holder = state::StateHolder::new()?;
            if let Ok(keypair) = keypair_seal::unseal(&sealed_key) {
                let conn: Box<dyn Connection> = get_connection(secret_connection.as_ref());
                let mut session = tmkms_light::session::Session::new(
                    config,
                    conn,
                    keypair,
                    initial_state.into(),
                    state_holder,
                );
                loop {
                    if let Err(e) = session.request_loop() {
                        error!("request error: {}", e);
                    }
                    let conn: Box<dyn Connection> = get_connection(secret_connection.as_ref());
                    session.reset_connection(conn);
                }
            } else {
                error!("unsealing failed");
            }
        }
        Err(e) => {
            error!("init error: {}", e);
        }
    }
    Ok(())
}
