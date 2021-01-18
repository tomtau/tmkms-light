use anomaly::{fail, format_err};
use nix::sys::socket::SockAddr;
use std::{
    fs,
    io::{self, prelude::*},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};
use tempfile::NamedTempFile;
use tmkms_light::chain::state::{consensus, StateError, StateErrorKind};
use tracing::{debug, info, warn};
use vsock::VsockStream;

pub struct StateSyncer {
    state_file_path: PathBuf,
    vsock_conn: VsockStream,
    state: consensus::State,
}

impl StateSyncer {
    pub fn new<P: AsRef<Path>>(
        path: P,
        vsock_cid: u32,
        vsock_port: u32,
    ) -> Result<Self, StateError> {
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

        let sockaddr = SockAddr::new_vsock(vsock_cid, vsock_port);
        const MAX_ATTEMPTS: u64 = 5;
        let mut vsock_conn = vsock::VsockStream::connect(&sockaddr);
        let mut attempt = 1;
        while let Err(e) = vsock_conn {
            if attempt == MAX_ATTEMPTS {
                return Err(format_err!(
                    StateErrorKind::SyncError,
                    "failed to connect to vsock: {}",
                    e
                )
                .into());
            }
            warn!(
                "failed to connect to the state persistence socket {}; retrying {}",
                e, attempt
            );
            thread::sleep(Duration::new(attempt, 0));
            attempt += 1;
            vsock_conn = vsock::VsockStream::connect(&sockaddr);
        }
        let mut vsock_conn = vsock_conn.unwrap();
        if let Err(e) = bincode::serialize_into(&mut vsock_conn, &state) {
            warn!("error serializing to bincode {}", e);
        }
        Ok(Self {
            state_file_path,
            vsock_conn,
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
    pub fn launch_syncer(mut self) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            info!("getting states from enclave for local persistence");
            loop {
                if let Ok(consensus_state) = bincode::deserialize_from(&mut self.vsock_conn) {
                    self.state = consensus_state;
                    if let Err(e) = Self::persist_state(&self.state_file_path, &self.state) {
                        warn!("state persistence failed: {}", e);
                    }
                } else {
                    warn!("failed to deserialize state from vsock connection");
                    thread::sleep(Duration::new(1, 0));
                }
            }
        })
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
