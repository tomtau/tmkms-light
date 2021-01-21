use anomaly::format_err;
use nix::sys::socket::SockAddr;
use std::io;
use std::os::unix::io::AsRawFd;
use tmkms_light::chain::state::{consensus, PersistStateSync, State, StateError, StateErrorKind};
use tmkms_nitro_helper::VSOCK_PROXY_CID;
use tracing::debug;
use vsock::VsockStream;

#[derive(Debug, Clone)]
pub struct StateHolder {
    state_conn: VsockStream,
}

impl StateHolder {
    pub fn new(vsock_port: u32) -> io::Result<Self> {
        let addr = SockAddr::new_vsock(VSOCK_PROXY_CID, vsock_port);
        let state_conn = vsock::VsockStream::connect(&addr)?;
        debug!("state vsock port: {}", vsock_port);
        debug!("state peer addr: {:?}", state_conn.peer_addr());
        debug!("state local addr: {:?}", state_conn.local_addr());
        debug!("state fd: {}", state_conn.as_raw_fd());
        Ok(Self { state_conn })
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
        debug!("state peer addr: {:?}", self.state_conn.peer_addr());
        debug!("state local addr: {:?}", self.state_conn.local_addr());
        debug!("state fd: {}", self.state_conn.as_raw_fd());
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
