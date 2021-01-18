use crate::nitro::VMADDR_CID_ANY;
use anomaly::format_err;
use nix::sys::socket::SockAddr;
use std::io;
use tmkms_light::chain::state::{consensus, PersistStateSync, State, StateError, StateErrorKind};
use tracing::{debug, info, warn};
use vsock::{VsockListener, VsockStream};

#[derive(Debug, Clone)]
pub struct StateHolder {
    state_conn: VsockStream,
}

impl StateHolder {
    pub fn new(vsock_port: u32) -> io::Result<Self> {
        let addr = SockAddr::new_vsock(VMADDR_CID_ANY, vsock_port);
        let listener = VsockListener::bind(&addr)?;
        info!("waiting for state connection {}", addr);
        let mut state_conn = listener.accept();
        while let Err(e) = state_conn {
            warn!("error getting state connection: {}", e);
            state_conn = listener.accept();
        }
        Ok(Self {
            state_conn: state_conn?.0,
        })
    }
}

impl PersistStateSync for StateHolder {
    fn load_state(&mut self) -> Result<State, StateError> {
        let consensus_state: consensus::State = bincode::deserialize_from(&mut self.state_conn)
            .map_err(|e| format_err!(StateErrorKind::SyncError, "error parsing: {}", e))?;
        Ok(State::from(consensus_state))
    }

    fn persist_state(&mut self, new_state: &consensus::State) -> Result<(), StateError> {
        debug!("writing new consensus state to state conn");

        bincode::serialize_into(&mut self.state_conn, &new_state).map_err(|e| {
            format_err!(
                StateErrorKind::SyncError,
                "error serializing to bincode {}",
                e
            )
        })?;

        debug!("successfully wrote new consensus state to state connection");

        Ok(())
    }
}
