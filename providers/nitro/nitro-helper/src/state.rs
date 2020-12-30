use anomaly::{fail, format_err};
use nix::sys::socket::SockAddr;
use std::os::unix::net::UnixStream;
use std::thread;
use std::{
    fs,
    io::{self, prelude::*},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use tmkms_light::chain::state::{consensus, StateError, StateErrorKind};
use tracing::{debug, info, warn};
use vsock::{VsockListener, VsockStream};

use crate::shared::VSOCK_PROXY_CID;

pub struct StateSyncer {
    state_file_path: PathBuf,
    vsock_listener: VsockListener,
    state: consensus::State,
}

impl StateSyncer {
    pub fn new<P: AsRef<Path>>(path: P, vsock_port: u32) -> Result<Self, StateError> {
        let state_file_path = path.as_ref().to_owned();
        let state = match fs::read_to_string(&path) {
            Ok(state_json) => {
                let consensus_state: consensus::State =
                    serde_json::from_str(&state_json).map_err(|e| {
                        format_err!(
                            StateErrorKind::SyncError,
                            "error parsing {}: {}",
                            path.as_ref().display(),
                            e
                        )
                    })?;

                Ok(consensus_state)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Self::write_initial_state(&state_file_path)
            }
            Err(e) => fail!(
                StateErrorKind::SyncError,
                "error reading {}: {}",
                path.as_ref().display(),
                e
            ),
        }?;

        let sockaddr = SockAddr::new_vsock(VSOCK_PROXY_CID, vsock_port);
        let vsock_listener = VsockListener::bind(&sockaddr).map_err(|e| {
            format_err!(
                StateErrorKind::SyncError,
                "failed to listen on vsock: {}",
                e
            )
        })?;

        Ok(Self {
            state_file_path,
            vsock_listener,
            state,
        })
    }

    /// Write the initial state to the given path on disk
    fn write_initial_state(path: &PathBuf) -> Result<consensus::State, StateError> {
        let mut consensus_state = consensus::State::default();

        // TODO(tarcieri): correct upstream `tendermint-rs` default height to 0
        // Set the initial block height to 0 to indicate we've never signed a block
        consensus_state.height = 0u32.into();

        Self::persist_state(path, &consensus_state)?;

        Ok(consensus_state)
    }

    /// Launches the state syncer
    pub fn launch_syncer(mut self) {
        thread::spawn(move || {
            info!("listening for enclave persistence");
            for conn in self.vsock_listener.incoming() {
                match conn {
                    Ok(mut stream) => {
                        info!("vsock persistence connection established");
                        if let Err(e) = bincode::serialize_into(&mut stream, &self.state) {
                            warn!("error serializing to bincode {}", e);
                        } else {
                            loop {
                                if let Ok(consensus_state) = bincode::deserialize_from(&mut stream)
                                {
                                    self.state = consensus_state;
                                    if let Err(e) =
                                        Self::persist_state(&self.state_file_path, &self.state)
                                    {
                                        warn!("state persistence failed: {}", e);
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
        });
    }

    fn persist_state(path: &PathBuf, new_state: &consensus::State) -> Result<(), StateError> {
        debug!(
            "writing new consensus state to {}: {:?}",
            path.display(),
            &new_state
        );

        let json = serde_json::to_string(&new_state).map_err(|e| {
            format_err!(
                StateErrorKind::SyncError,
                "error serializing to json {}: {}",
                path.display(),
                e
            )
        })?;

        let state_file_dir = path.parent().unwrap_or_else(|| {
            panic!("state file cannot be root directory");
        });

        let mut state_file = NamedTempFile::new_in(state_file_dir).map_err(|e| {
            format_err!(
                StateErrorKind::SyncError,
                "error creating a named temp file {}: {}",
                path.display(),
                e
            )
        })?;
        state_file.write_all(json.as_bytes()).map_err(|e| {
            format_err!(
                StateErrorKind::SyncError,
                "error writing {}: {}",
                path.display(),
                e
            )
        })?;
        state_file.persist(&path).map_err(|e| {
            format_err!(
                StateErrorKind::SyncError,
                "error persisting {}: {}",
                path.display(),
                e
            )
        })?;

        debug!(
            "successfully wrote new consensus state to {}",
            path.display(),
        );

        Ok(())
    }
}
