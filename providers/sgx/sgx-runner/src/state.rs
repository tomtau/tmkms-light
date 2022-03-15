use std::os::unix::net::UnixStream;
use std::thread;
use std::{
    fs,
    io::{self, prelude::*},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use tmkms_light::chain::state::{consensus, StateError};
use tmkms_light::utils::read_u16_payload;
use tracing::{debug, warn};

pub struct StateSyncer {
    state_file_path: PathBuf,
    stream_to_enclave: UnixStream,
}

impl StateSyncer {
    pub fn new<P: AsRef<Path>>(
        path: P,
        stream_to_enclave: UnixStream,
    ) -> Result<(Self, consensus::State), StateError> {
        let state_file_path = path.as_ref().to_owned();
        let state = match fs::read_to_string(&path) {
            Ok(state_json) => {
                let consensus_state: consensus::State = serde_json::from_str(&state_json)
                    .map_err(|e| StateError::sync_parse_error("error parsing".into(), e))?;

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
        Ok((
            Self {
                state_file_path,
                stream_to_enclave,
            },
            state,
        ))
    }

    /// load state from the provided vsock stream
    fn sync_from_stream(&mut self) -> Result<consensus::State, StateError> {
        let json_raw = read_u16_payload(&mut self.stream_to_enclave)
            .map_err(|e| StateError::sync_other_error(e.to_string()))?;

        serde_json::from_slice(&json_raw)
            .map_err(|e| StateError::sync_parse_error("failed to deserialize state".into(), e))
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

    /// Launches the state syncer
    pub fn launch_syncer(mut self) {
        thread::spawn(move || loop {
            if let Ok(ref consensus_state) = self.sync_from_stream() {
                if let Err(e) = Self::persist_state(&self.state_file_path, consensus_state) {
                    warn!("state persistence failed: {}", e);
                }
            }
        });
    }

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
