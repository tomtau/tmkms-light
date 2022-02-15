//! Copyright (c) 2018-2021 Iqlusion Inc. (licensed under the Apache License, Version 2.0)
//! Modifications Copyright (c) 2021, Foris Limited (licensed under the Apache License, Version 2.0)

use crate::{
    chain::state::{PersistStateSync, State, StateError, StateErrorDetail},
    config::validator::ValidatorConfig,
    connection::Connection,
    error::Error,
    rpc::{ChainIdErrorType, DoubleSignErrorType, Request, Response},
};
use ed25519_dalek::{Keypair, Signer};
use std::time::Instant;
use tendermint_proto::privval::PingResponse;
use tracing::{debug, error, info};

/// Encrypted or plain session with a validator node
pub struct Session<S: PersistStateSync> {
    /// Validator configuration options
    config: ValidatorConfig,

    /// connection to a validator node
    connection: Box<dyn Connection>,

    /// consensus signing key
    signing_key: Keypair,

    /// consensus state
    state: State,

    /// consensus state persistence
    state_syncer: S,
}

impl<S: PersistStateSync> Session<S> {
    pub fn reset_connection(&mut self, connection: Box<dyn Connection>) {
        self.connection = connection;
    }

    pub fn new(
        config: ValidatorConfig,
        connection: Box<dyn Connection>,
        signing_key: Keypair,
        state: State,
        state_syncer: S,
    ) -> Self {
        Self {
            config,
            connection,
            signing_key,
            state,
            state_syncer,
        }
    }

    /// Check chain id matches the configured one
    fn check_chain_id(&self, chain_id: &tendermint::chain::Id) -> Result<(), Error> {
        if chain_id == &self.config.chain_id {
            Ok(())
        } else {
            Err(Error::chain_id_error(chain_id.to_string()))
        }
    }

    /// If a max block height is configured, ensure the block we're signing
    /// doesn't exceed it
    fn check_max_height(&self, request_height: i64) -> Result<(), Error> {
        if let Some(max_height) = self.config.max_height {
            if request_height > max_height.value() as i64 {
                return Err(Error::exceed_max_height(request_height, max_height.into()));
            }
        }
            Ok(())
    }

    /// Main request loop
    pub fn request_loop(&mut self) -> Result<(), Error> {
        while self.handle_request()? {}
        Ok(())
    }

    /// Handle an incoming request from the validator
    fn handle_request(&mut self) -> Result<bool, Error> {
        let request = Request::read(&mut self.connection)?;
        debug!(
            "[{}] received request: {:?}",
            &self.config.chain_id, &request
        );
        let response = match request {
            Request::SignProposal(req) => {
                if self.check_chain_id(&req.chain_id).is_err() {
                    Response::invalid_chain_id(ChainIdErrorType::Proposal, &req.chain_id)
                } else {
                    self.check_max_height(req.proposal.height.into())?;
                    let request_state = State::from(req.clone());
                    let req_cs = request_state.consensus_state();
                    match self
                        .state
                        .check_update_consensus_state(req_cs.clone(), &mut self.state_syncer)
                    {
                        Ok(_) => {
                            let signable_bytes = req.to_signable_vec().map_err(|e| {
                                Error::signing_tendermint_error("can't get proposal signable bytes".into(), e.into())
                            })?;
                            let started_at = Instant::now();
                            let signature = self.signing_key.sign(&signable_bytes);
                            info!(
                                "[{}] signed:{} at h/r/s {} ({} ms)",
                                &self.config.chain_id,
                                req_cs.block_id_prefix(),
                                req_cs,
                                started_at.elapsed().as_millis(),
                            );
                            Response::proposal_response(req, signature)
                        }
                        Err(e) if e == StateError::double_sign_error() => {
                            // Report double signing error back to the validator
                            let original_block_id = self.state.consensus_state().block_id_prefix();

                            error!(
                                "[{}] attempted double sign at h/r/s: {} ({} != {})",
                                &self.config.chain_id,
                                req_cs,
                                original_block_id,
                                req_cs.block_id_prefix()
                            );

                            Response::double_sign(
                                DoubleSignErrorType::Proposal,
                                req_cs.height.into(),
                            )
                        }
                        Err(e) => Err(Error::signing_state_error("failed signing proposal".into(), e)),
                    }
                }
            }
            Request::SignVote(req) => {
                if self.check_chain_id(&req.chain_id).is_err() {
                    Response::invalid_chain_id(ChainIdErrorType::Vote, &req.chain_id)
                } else {
                    self.check_max_height(req.vote.height.into())?;
                    let request_state = State::from(req.clone());
                    let req_cs = request_state.consensus_state();
                    match self
                        .state
                        .check_update_consensus_state(req_cs.clone(), &mut self.state_syncer)
                    {
                        Ok(_) => {
                            let signable_bytes = req.to_signable_vec().map_err(|e| {
                                Err(Error::signing_tendermint_error("cannot get vote signable bytes".to_string(), e.into()))
                            })?;
                            let started_at = Instant::now();
                            let signature = self.signing_key.sign(&signable_bytes);
                            info!(
                                "[{}] signed:{} at h/r/s {} ({} ms)",
                                &self.config.chain_id,
                                req_cs.block_id_prefix(),
                                req_cs,
                                started_at.elapsed().as_millis(),
                            );
                            Response::vote_response(req, signature)
                        }
                        Err(StateError::DoubleSign) => {
                            // Report double signing error back to the validator
                            let original_block_id = self.state.consensus_state().block_id_prefix();

                            error!(
                                "[{}] attempted double sign at h/r/s: {} ({} != {})",
                                &self.config.chain_id,
                                req_cs,
                                original_block_id,
                                req_cs.block_id_prefix()
                            );

                            Response::double_sign(DoubleSignErrorType::Vote, req_cs.height.into())
                        }
                        Err(e) => Err(Error::signing_state_error("failed signing vote".into(), e)),
                    }
                }
            }
            // non-signable requests:
            Request::ReplyPing(_) => Response::Ping(PingResponse {}),
            Request::ShowPublicKey(ref req) => {
                if self.check_chain_id(&req.chain_id).is_err() {
                    Response::invalid_chain_id(ChainIdErrorType::Pubkey, &req.chain_id)
                } else {
                    Response::PublicKey(self.signing_key.public.into())
                }
            }
        };
        debug!(
            "[{}] sending response: {:?}",
            &self.config.chain_id, &response
        );

        let response_bytes = response.encode()?;
        self.connection
            .write_all(&response_bytes)
            .map_err(|e| Error::io_error("write response failed".into(), e))?;

        Ok(true)
    }
}
