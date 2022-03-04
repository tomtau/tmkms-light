use std::{
    fs,
    io::{self, prelude::*},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use tmkms_light::chain::state::{consensus, PersistStateSync, State, StateError};
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
        let consensus_state = consensus::State {
            height: 0u32.into(),
            ..Default::default()
        };

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
                        StateError::sync_parse_error(self.state_file_path.display().to_string(), e)
                    })?;

                Ok(State::from(consensus_state))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => self.write_initial_state(),
            Err(e) => Err(StateError::sync_error(
                self.state_file_path.display().to_string(),
                e,
            )),
        }
    }

    fn persist_state(&mut self, new_state: &consensus::State) -> Result<(), StateError> {
        debug!(
            "writing new consensus state to {}: {:?}",
            self.state_file_path.display(),
            &new_state
        );

        let json = serde_json::to_string(&new_state).map_err(|e| {
            StateError::sync_parse_error(self.state_file_path.display().to_string(), e)
        })?;

        let state_file_dir = self.state_file_path.parent().unwrap_or_else(|| {
            panic!("state file cannot be root directory");
        });

        let mut state_file = NamedTempFile::new_in(state_file_dir)
            .map_err(|e| StateError::sync_error(self.state_file_path.display().to_string(), e))?;
        state_file
            .write_all(json.as_bytes())
            .map_err(|e| StateError::sync_error(self.state_file_path.display().to_string(), e))?;
        state_file.persist(&self.state_file_path).map_err(|e| {
            StateError::sync_error(self.state_file_path.display().to_string(), e.error)
        })?;

        debug!(
            "successfully wrote new consensus state to {}",
            self.state_file_path.display(),
        );

        Ok(())
    }
}
