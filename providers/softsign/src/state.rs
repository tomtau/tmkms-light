use anomaly::{fail, format_err};
use std::{
    fs,
    io::{self, prelude::*},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use tmkms_light::chain::state::{consensus, PersistStateSync, State, StateError, StateErrorKind};
use tracing::debug;

pub struct StateHolder {
    state_file_path: PathBuf,
}

impl StateHolder {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            state_file_path: path.as_ref().to_owned(),
        }
    }

    /// Write the initial state to the given path on disk
    fn write_initial_state(&mut self) -> Result<State, StateError> {
        let mut consensus_state = consensus::State::default();

        // TODO(tarcieri): correct upstream `tendermint-rs` default height to 0
        // Set the initial block height to 0 to indicate we've never signed a block
        consensus_state.height = 0u32.into();

        self.persist_state(&consensus_state)?;

        Ok(State::from(consensus_state))
    }
}

impl PersistStateSync for StateHolder {
    fn load_state(&mut self) -> Result<State, StateError> {
        match fs::read_to_string(&self.state_file_path) {
            Ok(state_json) => {
                let consensus_state: consensus::State =
                    serde_json::from_str(&state_json).map_err(|e| {
                        format_err!(
                            StateErrorKind::SyncError,
                            "error parsing {}: {}",
                            self.state_file_path.display(),
                            e
                        )
                    })?;

                Ok(State::from(consensus_state))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => self.write_initial_state(),
            Err(e) => fail!(
                StateErrorKind::SyncError,
                "error reading {}: {}",
                self.state_file_path.display(),
                e
            ),
        }
    }

    fn persist_state(&mut self, new_state: &consensus::State) -> Result<(), StateError> {
        debug!(
            "writing new consensus state to {}: {:?}",
            self.state_file_path.display(),
            &new_state
        );

        let json = serde_json::to_string(&new_state).map_err(|e| {
            format_err!(
                StateErrorKind::SyncError,
                "error serializing to json {}: {}",
                self.state_file_path.display(),
                e
            )
        })?;

        let state_file_dir = self.state_file_path.parent().unwrap_or_else(|| {
            panic!("state file cannot be root directory");
        });

        let mut state_file = NamedTempFile::new_in(state_file_dir).map_err(|e| {
            format_err!(
                StateErrorKind::SyncError,
                "error creating a named temp file {}: {}",
                self.state_file_path.display(),
                e
            )
        })?;
        state_file.write_all(json.as_bytes()).map_err(|e| {
            format_err!(
                StateErrorKind::SyncError,
                "error writing {}: {}",
                self.state_file_path.display(),
                e
            )
        })?;
        state_file.persist(&self.state_file_path).map_err(|e| {
            format_err!(
                StateErrorKind::SyncError,
                "error persisting {}: {}",
                self.state_file_path.display(),
                e
            )
        })?;

        debug!(
            "successfully wrote new consensus state to {}",
            self.state_file_path.display(),
        );

        Ok(())
    }
}
