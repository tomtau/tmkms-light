use crate::shared::{SealedKeyData, SgxInitRequest, SgxInitResponse};
use crate::state::StateSyncer;
use aesm_client::AesmClient;
use enclave_runner::{
    usercalls::{AsyncStream, UsercallExtension},
    EnclaveBuilder,
};
use sgxs_loaders::isgx::Device;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::{future::Future, io, pin::Pin};
/// type alias for outputs in UsercallExtension async return type
type UserCallStream = io::Result<Option<Box<dyn AsyncStream>>>;

/// custom runner for tmkms <-> enclave app communication
/// TODO: Windows support (via random TCP or custom in-memory stream)?
#[derive(Debug)]
struct TmkmsSgxRunner {
    init_stream: UnixStream,
    state_stream: UnixStream,
    tm_conn: Option<UnixStream>,
}

impl UsercallExtension for TmkmsSgxRunner {
    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
        _peer_addr: Option<&'future mut String>,
    ) -> Pin<Box<dyn Future<Output = UserCallStream> + 'future>> {
        async fn connect_stream_inner(this: &TmkmsSgxRunner, addr: &str) -> UserCallStream {
            match addr {
                "init" => {
                    let stream = tokio::net::UnixStream::from_std(this.init_stream.try_clone()?)?;
                    Ok(Some(Box::new(stream)))
                }
                "state" => {
                    let stream = tokio::net::UnixStream::from_std(this.state_stream.try_clone()?)?;
                    Ok(Some(Box::new(stream)))
                }
                "tendermint" => {
                    if let Some(ref conn) = this.tm_conn {
                        let stream = tokio::net::UnixStream::from_std(conn.try_clone()?)?;
                        Ok(Some(Box::new(stream)))
                    } else {
                        Ok(None)
                    }
                }
                _ => Ok(None),
            }
        }
        Box::pin(connect_stream_inner(self, addr))
    }
}

/// controller for launching the enclave app and providing the communication with it
pub struct TmkmsSgxSigner {
    stream_to_enclave: UnixStream,
    enclave_app_thread: thread::JoinHandle<()>,
}

impl TmkmsSgxSigner {
    /// launches the `tmkms-light-sgx-app` from the provided path
    pub fn launch_enclave_app<P: AsRef<Path>>(
        sgxs_path: P,
        tm_conn: Option<UnixStream>,
        state_path: P,
    ) -> io::Result<Self> {
        let (stream_to_enclave, init_stream) = UnixStream::pair()?;
        let (state_from_enclave, state_stream) = UnixStream::pair()?;
        let state_syncer = StateSyncer::new(state_path, state_from_enclave).expect("state syncer");
        state_syncer.launch_syncer();
        let runner = TmkmsSgxRunner {
            init_stream,
            state_stream,
            tm_conn,
        };
        let mut device = Device::new()?
            .einittoken_provider(AesmClient::new())
            .build();
        let mut enclave_builder = EnclaveBuilder::new(sgxs_path.as_ref());
        enclave_builder.coresident_signature()?;

        enclave_builder.usercall_extension(runner);
        let enclave = enclave_builder
            .build(&mut device)
            .expect("Failed to build the enclave app");
        let enclave_app_thread = thread::spawn(|| {
            enclave
                .run()
                .expect("Failed to start `tmkms-sgx-app` enclave")
        });
        Ok(Self {
            stream_to_enclave,
            enclave_app_thread,
        })
    }

    /// req-rep helper
    fn exchange(&self, request: SgxInitRequest) -> bincode::Result<SgxInitResponse> {
        bincode::serialize_into(&self.stream_to_enclave, &request)?;
        bincode::deserialize_from(&self.stream_to_enclave)
    }

    /// generate a new keypair
    pub fn keygen(self) -> Result<SealedKeyData, ()> {
        match self.exchange(SgxInitRequest::KeyGen {
            cloud_backup_key: None,
        }) {
            Ok(SgxInitResponse {
                sealed_key_data, ..
            }) => {
                self.enclave_app_thread
                    .join()
                    .expect("enclave thread finished");
                Ok(sealed_key_data)
            }
            _ => Err(()),
        }
    }
}
