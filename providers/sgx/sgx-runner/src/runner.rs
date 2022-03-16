use crate::shared::{RemoteConnectionConfig, SealedKeyData, SgxInitRequest, SgxInitResponse};
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
use std::{fs, path::PathBuf};
use std::{future::Future, io, pin::Pin};
use tendermint::consensus;
use tendermint_config::net;
use tmkms_light::config::validator::ValidatorConfig;
use tmkms_light::error::{io_error_wrap, Error};
use tmkms_light::utils::read_u16_payload;
use tracing::{debug, error};

/// type alias for outputs in UsercallExtension async return type
type UserCallStream = io::Result<Option<Box<dyn AsyncStream>>>;

/// custom runner for tmkms <-> enclave app communication
/// TODO: Windows support (via random TCP or custom in-memory stream)?
#[derive(Debug)]
struct TmkmsSgxRunner {
    init_stream: UnixStream,
    state_stream: UnixStream,
    tm_conn: Option<PathBuf>,
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
                    if let Some(ref path) = this.tm_conn {
                        let stream = tokio::net::UnixStream::connect(path).await?;
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
    enclave_app_thread: thread::JoinHandle<Result<(), Error>>,
}

impl TmkmsSgxSigner {
    /// returns the state persistence helper, the last persisted state,
    /// and the unix socket to pass to the enclave runner
    pub fn get_state_syncer<P: AsRef<Path>>(
        state_path: P,
    ) -> Result<(StateSyncer, consensus::State, UnixStream), Error> {
        let (state_from_enclave, state_stream) = UnixStream::pair()
            .map_err(|e| Error::io_error("failed to get state unix socket pair".into(), e))?;

        let (state_syncer, state) = StateSyncer::new(state_path, state_from_enclave)
            .map_err(|e| io_error_wrap("failed to get state persistence helper".into(), e))?;
        Ok((state_syncer, state, state_stream))
    }

    /// launches the `tmkms-light-sgx-app` from the provided path
    pub fn launch_enclave_app<P: AsRef<Path>>(
        sgxs_path: P,
        tm_conn: Option<PathBuf>,
        state_syncer: StateSyncer,
        state_stream: UnixStream,
        args: &[&[u8]],
    ) -> io::Result<Self> {
        let (stream_to_enclave, init_stream) = UnixStream::pair()?;
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
        enclave_builder.forward_panics(true);
        enclave_builder.args(args);
        match enclave_builder.build(&mut device) {
            Ok(enclave) => {
                let enclave_app_thread = thread::spawn(|| {
                    enclave
                        .run()
                        .map_err(|e| io_error_wrap("enclave runner error".into(), e))
                });
                Ok(Self {
                    stream_to_enclave,
                    enclave_app_thread,
                })
            }
            Err(e) => {
                error!("failed to build the enclave app: {:?}", e);
                Err(io::ErrorKind::Other.into())
            }
        }
    }

    /// get the response from the enclave via the init stream
    pub fn get_init_response(mut self) -> Result<SgxInitResponse, Error> {
        debug!("waiting for response");
        let response_bytes = read_u16_payload(&mut self.stream_to_enclave)?;
        let resp: SgxInitResponse = serde_json::from_slice(&response_bytes)
            .map_err(|e| io_error_wrap("error deserializing response".into(), e))?;
        self.join_enclave_thread()?;
        Ok(resp)
    }

    /// get the request payload that's passed as an argument to the enclave
    /// to start up the tmkms handling
    pub fn get_start_request_bytes<P: AsRef<Path>>(
        sealed_key_path: P,
        config: ValidatorConfig,
        initial_state: consensus::State,
        remote_conn: Option<(net::Address, P)>,
    ) -> Result<Vec<u8>, Error> {
        let sealed_key: SealedKeyData = serde_json::from_slice(
            &fs::read(sealed_key_path)
                .map_err(|e| Error::io_error("error reading sealed consensus key".into(), e))?,
        )
        .map_err(|_e| Error::invalid_key_error())?;
        let secret_connection = match remote_conn {
            Some((
                net::Address::Tcp {
                    peer_id,
                    host,
                    port,
                },
                id_path,
            )) => {
                let sealed_id_key: SealedKeyData = serde_json::from_slice(
                    &fs::read(id_path)
                        .map_err(|e| Error::io_error("error reading id sealed key".into(), e))?,
                )
                .map_err(|_e| Error::invalid_key_error())?;
                Some(RemoteConnectionConfig {
                    peer_id,
                    host,
                    port,
                    sealed_key: sealed_id_key,
                })
            }
            _ => None,
        };
        let req_bytes = serde_json::to_vec(&SgxInitRequest::Start {
            sealed_key,
            config,
            secret_connection,
            initial_state,
        })
        .map_err(|e| io_error_wrap("failed to obtain the start request payload".into(), e))?;
        Ok(req_bytes)
    }

    fn join_enclave_thread(self) -> Result<(), Error> {
        match self.enclave_app_thread.join() {
            Ok(Ok(_)) => Ok(()),
            Err(_e) => Err(Error::panic_error()),
            Ok(Err(e)) => Err(e),
        }
    }

    /// run the main privval handling
    pub fn start(self) -> Result<(), Error> {
        self.join_enclave_thread()
    }
}
