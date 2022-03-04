use crate::shared::VSOCK_HOST_CID;
use std::os::unix::io::AsRawFd;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::thread;
use std::{
    fs,
    io::{self, prelude::*},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use tmkms_light::chain::state::{consensus, StateError};
use tmkms_light::error::Error;
use tmkms_light::utils::{read_u16_payload, write_u16_payload};
use tracing::{debug, info, warn};
use vsock::{SockAddr, VsockListener, VsockStream};

/// helps the enclave to load the state previously persisted on the host
/// + to persist new states
pub struct StateSyncer {
    state_file_path: PathBuf,
    vsock_listener: VsockListener,
    state: consensus::State,
}

impl StateSyncer {
    /// creates a new state file or loads the previous one
    /// and binds a listener for incoming vsock connections from the enclave
    /// on the proxy CID on the provided port
    pub fn new<P: AsRef<Path>>(path: P, vsock_port: u32) -> Result<Self, StateError> {
        let state_file_path = path.as_ref().to_owned();
        let state = match fs::read_to_string(&path) {
            Ok(state_json) => {
                let consensus_state: consensus::State =
                    serde_json::from_str(&state_json).map_err(|e| {
                        StateError::sync_parse_error(path.as_ref().display().to_string(), e)
                    })?;

                Ok(consensus_state)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Self::write_initial_state(&state_file_path)
            }
            Err(e) => Err(StateError::sync_error(
                path.as_ref().display().to_string(),
                e,
            )),
        }?;

        let sockaddr = SockAddr::new_vsock(VSOCK_HOST_CID, vsock_port);
        let vsock_listener = VsockListener::bind(&sockaddr)
            .map_err(|e| StateError::sync_error("vsock".to_string(), e))?;

        Ok(Self {
            state_file_path,
            vsock_listener,
            state,
        })
    }

    /// Write the initial state to the given path on disk
    fn write_initial_state(path: &Path) -> Result<consensus::State, StateError> {
        let consensus_state = consensus::State {
            height: 0u32.into(),
            ..Default::default()
        };

        Self::persist_state(path, &consensus_state)?;

        Ok(consensus_state)
    }

    /// dump the current state to the provided vsock stream
    fn sync_to_stream(&self, stream: &mut VsockStream) -> Result<(), StateError> {
        let json_raw = serde_json::to_vec(&self.state)
            .map_err(|e| StateError::sync_parse_error("vsock".into(), e))?;
        write_u16_payload(stream, &json_raw).map_err(|e| StateError::sync_error("vsock".into(), e))
    }

    /// load state from the provided vsock stream
    fn sync_from_stream(mut stream: &mut VsockStream) -> Result<consensus::State, Error> {
        let json_raw = read_u16_payload(&mut stream)?;
        // .map_err(|e| StateError::sync_error("vsock".into(), e))?;
        serde_json::from_slice(&json_raw).map_err(|e| {
            Error::io_error(
                "parse error".into(),
                std::io::Error::new(std::io::ErrorKind::Other, e),
            )
        })
    }

    /// Launches the state syncer, when get data from stop_recv, the thread will be finished
    pub fn launch_syncer(mut self, stop_recv: Receiver<()>) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            info!("listening for enclave persistence");
            for conn in self.vsock_listener.incoming() {
                match conn {
                    Ok(mut stream) => {
                        info!("vsock persistence connection established");
                        debug!("state peer addr: {:?}", stream.peer_addr());
                        debug!("state local addr: {:?}", stream.local_addr());
                        debug!("state fd: {}", stream.as_raw_fd());

                        if let Err(e) = self.sync_to_stream(&mut stream) {
                            warn!("error serializing to json {}", e);
                        } else {
                            loop {
                                if let Ok(consensus_state) = Self::sync_from_stream(&mut stream) {
                                    self.state = consensus_state;
                                    if let Err(e) =
                                        Self::persist_state(&self.state_file_path, &self.state)
                                    {
                                        warn!("state persistence failed: {}", e);
                                    }
                                    match stop_recv.try_recv() {
                                        Ok(()) | Err(TryRecvError::Disconnected) => {
                                            warn!("stop state persistence");
                                            return;
                                        }
                                        Err(TryRecvError::Empty) => continue,
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Vsock connection failed: {}", e);
                    }
                }
            }
        })
    }

    /// write the new state into a file on the host
    fn persist_state(path: &Path, new_state: &consensus::State) -> Result<(), StateError> {
        debug!(
            "writing new consensus state to {}: {:?}",
            path.display(),
            &new_state
        );

        let json = serde_json::to_string(&new_state)
            .map_err(|e| StateError::sync_parse_error(path.display().to_string(), e))?;

        let state_file_dir = path.parent().unwrap_or_else(|| {
            panic!("state file cannot be root directory");
        });

        let mut state_file = NamedTempFile::new_in(state_file_dir)
            .map_err(|e| StateError::sync_error(path.display().to_string(), e))?;
        state_file
            .write_all(json.as_bytes())
            .map_err(|e| StateError::sync_error(path.display().to_string(), e))?;
        state_file
            .persist(&path)
            .map_err(|e| StateError::sync_error(path.display().to_string(), e.error))?;

        debug!(
            "successfully wrote new consensus state to {}",
            path.display(),
        );

        Ok(())
    }
}
