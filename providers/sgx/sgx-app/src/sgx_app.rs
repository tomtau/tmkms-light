/// helpers for keypair sealing/unsealing
pub(crate) mod keypair_seal;
/// state persistence helper;
mod state;

/// helpers for cloud deployments (where CPU affinitity isn't guaranteed)
mod cloud;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use sgx_isa::{Report, Targetinfo};
use std::{io, net::TcpStream, thread, time::Duration};
use subtle::ConstantTimeEq;
use tendermint_p2p::secret_connection::{self, PublicKey, SecretConnection};
use tmkms_light::{
    connection::{Connection, PlainConnection},
    utils::write_u16_payload,
};
use tmkms_light_sgx_runner::{
    RemoteConnectionConfig, {SgxInitRequest, SgxInitResponse},
};
use tracing::{debug, error, info, warn};

fn get_secret_connection(config: &RemoteConnectionConfig) -> io::Result<Box<dyn Connection>> {
    let RemoteConnectionConfig {
        peer_id,
        host,
        port,
        sealed_key,
    } = config;
    let socket = TcpStream::connect(format!("{}:{}", host, port))?;
    // TODO: just unseal once in the caller
    if let Ok(identity_key) = keypair_seal::unseal(&sealed_key) {
        info!("KMS node ID: {}", PublicKey::from(&identity_key));

        let connection =
            SecretConnection::new(socket, identity_key, secret_connection::Version::V0_34)
                .map_err(|e| {
                    error!("secret connection failed: {}", e);
                    io::Error::from(io::ErrorKind::Other)
                })?;
        let actual_peer_id = connection.remote_pubkey().peer_id();

        // TODO: https://github.com/informalsystems/tendermint-rs/issues/786
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
            // TODO: https://github.com/informalsystems/tendermint-rs/issues/786
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

/// keeps retrying with approx. 1 sec sleep until it manages to connect to tendermint privval endpoint
/// (either TCP or Unix socket exposed via "tendermint" usercall extension)
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
/// `TcpStream` is either provided in tests or from the "init"
/// enclave runner's user call extension.
/// TODO: no need to pass the host_response stream for "Start"
pub fn entry(mut host_response: TcpStream, request: SgxInitRequest) -> io::Result<()> {
    let mut csprng = OsRng {};
    match request {
        SgxInitRequest::GenWrapKey { targetinfo } => {
            let targetinfo = targetinfo.unwrap_or_else(|| Targetinfo::from(Report::for_self()));
            let rsa_kp = cloud::generate_keypair(&mut csprng, targetinfo);
            if let Ok((wrap_pub_key, wrap_key_sealed, pub_key_report)) = rsa_kp {
                let response = SgxInitResponse::WrapKey {
                    wrap_key_sealed,
                    wrap_pub_key,
                    pub_key_report,
                };
                match serde_json::to_vec(&response) {
                    Ok(v) => {
                        debug!("writing response");
                        write_u16_payload(&mut host_response, &v)?;
                    }
                    Err(e) => {
                        error!("keygen error: {}", e);
                    }
                }
            } else {
                error!("sealing failed");
            }
        }
        SgxInitRequest::KeyGen { cloud_backup } => {
            let kp = Keypair::generate(&mut csprng);
            let cloud_backup_key_data =
                cloud_backup.and_then(|key| cloud::cloud_backup(&mut csprng, key, &kp).ok());
            if let Ok(sealed_key_data) = keypair_seal::seal(&mut csprng, &kp) {
                let response = SgxInitResponse::GenOrRecover {
                    sealed_key_data,
                    cloud_backup_key_data,
                };
                match serde_json::to_vec(&response) {
                    Ok(v) => {
                        debug!("writing response");
                        write_u16_payload(&mut host_response, &v)?;
                    }
                    Err(e) => {
                        error!("keygen error: {}", e);
                    }
                }
            } else {
                error!("sealing failed");
            }
        }
        SgxInitRequest::CloudRecover {
            cloud_backup,
            key_data,
        } => {
            if let Ok(sealed_key_data) =
                cloud::reseal_recover_cloud(&mut csprng, cloud_backup, key_data)
            {
                let response = SgxInitResponse::GenOrRecover {
                    sealed_key_data,
                    cloud_backup_key_data: None,
                };
                match serde_json::to_vec(&response) {
                    Ok(v) => {
                        debug!("writing response");
                        write_u16_payload(&mut host_response, &v)?;
                    }
                    Err(e) => {
                        error!("recovery error: {}", e);
                    }
                }
            } else {
                error!("recovery failed");
            }
        }
        SgxInitRequest::Start {
            sealed_key,
            config,
            secret_connection,
            initial_state,
        } => {
            let state_holder = state::StateHolder::new()?;
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
                return Err(io::ErrorKind::Other.into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use tmkms_light::utils::read_u16_payload;
    use tmkms_light_sgx_runner::CloudBackupKey;

    // can be run with `cargo test --target x86_64-fortanix-unknown-sgx`
    #[test]
    fn test_recover_flow() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let handler = std::thread::spawn(move || {
            while let Ok(Some(req)) = receiver.recv() {
                entry(TcpStream::connect(addr).unwrap(), req).expect("ok entry");
            }
        });
        sender
            .send(Some(SgxInitRequest::GenWrapKey { targetinfo: None }))
            .expect("send request0");
        let (mut stream_signer, _) = listener.accept().unwrap();
        let resp1 = read_u16_payload(&mut stream_signer).expect("response0");
        let response1: SgxInitResponse = serde_json::from_slice(&resp1).expect("response0");
        let (sealed_rsa_key, pubkey) = match response1 {
            SgxInitResponse::WrapKey {
                wrap_key_sealed,
                wrap_pub_key,
                ..
            } => (wrap_key_sealed, wrap_pub_key),
            _ => panic!("wrong response"),
        };
        let mut csprng = OsRng {};

        let backup_key = cloud::tests::get_wrapped_key(&mut csprng, pubkey);
        let cloud_backup = CloudBackupKey {
            sealed_rsa_key,
            backup_key,
        };
        let cloud_backup2 = cloud_backup.clone();
        sender
            .send(Some(SgxInitRequest::KeyGen {
                cloud_backup: Some(cloud_backup),
            }))
            .expect("send request1");
        let (mut stream_signer, _) = listener.accept().unwrap();
        let resp1 = read_u16_payload(&mut stream_signer).expect("response1");
        let response1: SgxInitResponse = serde_json::from_slice(&resp1).expect("response1");
        let (seal_key_request, cloud_backup_key_data) =
            response1.get_gen_response().expect("response1");
        sender
            .send(Some(SgxInitRequest::CloudRecover {
                cloud_backup: cloud_backup2,
                key_data: cloud_backup_key_data.expect("backup"),
            }))
            .expect("send request2");

        let (mut stream_signer, _) = listener.accept().unwrap();
        let resp2 = read_u16_payload(&mut stream_signer).expect("response2");
        let response2: SgxInitResponse = serde_json::from_slice(&resp2).expect("response2");
        let (seal_key_request2, _) = response2.get_gen_response().expect("response2");
        sender.send(None).expect("send request3");
        let _ = handler.join();
        assert_eq!(
            seal_key_request.seal_key_request.keyid,
            seal_key_request2.seal_key_request.keyid
        );
    }

    #[test]
    fn test_unseal() {
        let mut csprng = OsRng {};
        let kp = Keypair::generate(&mut csprng);
        let sealed_data = keypair_seal::seal(&mut csprng, &kp).unwrap();
        let mut mangled_sealed_data = sealed_data.clone();
        mangled_sealed_data.nonce[0] ^= 1;
        assert!(keypair_seal::unseal(&mangled_sealed_data).is_err());
        assert_eq!(
            keypair_seal::unseal(&sealed_data).unwrap().public,
            kp.public
        );
    }
}
