//! Connections to a validator (TCP/secret or Unix/local-plain socket)
//! Copyright (c) 2018-2021 Iqlusion Inc. (licensed under the Apache License, Version 2.0)
//! Modifications Copyright (c) 2021, Foris Limited (licensed under the Apache License, Version 2.0)

use std::io;
use std::marker::{Send, Sync};
use tendermint_p2p::secret_connection::SecretConnection;
use tracing::{debug, trace};

/// Connections to a validator
pub trait Connection: io::Read + io::Write + Sync + Send {}

/// Protocol implementation of the plain connection (Unix domain socket or local vsock-proxy)
pub struct PlainConnection<IoHandler> {
    socket: IoHandler,
}

impl<IoHandler> PlainConnection<IoHandler>
where
    IoHandler: io::Read + io::Write + Send + Sync,
{
    /// Create a new `PlainConnection` for the given socket
    pub fn new(socket: IoHandler) -> Self {
        Self { socket }
    }
}

impl<IoHandler> io::Read for PlainConnection<IoHandler>
where
    IoHandler: io::Read + io::Write + Send + Sync,
{
    fn read(&mut self, data: &mut [u8]) -> Result<usize, io::Error> {
        let r = self.socket.read(data);
        debug!("read tm connection: {:?}", r);
        trace!("read data: {:02X?}", data);
        r
    }
}

impl<IoHandler> io::Write for PlainConnection<IoHandler>
where
    IoHandler: io::Read + io::Write + Send + Sync,
{
    fn write(&mut self, data: &[u8]) -> Result<usize, io::Error> {
        let r = self.socket.write(data);
        debug!("write tm connection: {:?}", r);
        trace!("written: {:02X?}", data);
        r
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        trace!("flush");
        self.socket.flush()
    }
}

impl<T> Connection for SecretConnection<T> where T: io::Read + io::Write + Sync + Send {}
impl<T> Connection for PlainConnection<T> where T: io::Read + io::Write + Sync + Send {}
