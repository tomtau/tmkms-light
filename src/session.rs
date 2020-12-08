use crate::{
    chain::state::{PersistStateSync, State, StateErrorKind},
    config::validator::ValidatorConfig,
    connection::Connection,
    error::{Error, ErrorKind},
    rpc::{ChainIdErrorType, DoubleSignErrorType, Request, Response},
};
use anomaly::{fail, format_err};
use ed25519_dalek::{Keypair, Signature, Signer};
use std::borrow::BorrowMut;
use std::time::Instant;
use tendermint_proto::privval::PingResponse;
use tracing::{debug, error, info};

/// Encrypted or plain session with a validator node
pub struct Session {
    /// Validator configuration options
    config: ValidatorConfig,

    /// connection to a validator node
    connection: Box<dyn Connection>,

    /// consensus signing key
    signing_key: Keypair,

    /// consensus state
    state: State,

    /// consensus state persistence
    state_syncer: Box<dyn PersistStateSync>,
}

impl Session {
    /// Check chain id matches the configured one
    fn check_chain_id(&self, chain_id: &tendermint::chain::Id) -> Result<(), Error> {
        if chain_id == &self.config.chain_id {
            Ok(())
        } else {
            fail!(ErrorKind::ChainIdError, "invalid chain id: {:?}", chain_id)
        }
    }

    /// If a max block height is configured, ensure the block we're signing
    /// doesn't exceed it
    fn check_max_height(&self, request_height: i64) -> Result<(), Error> {
        if let Some(max_height) = self.config.max_height {
            if request_height > max_height.value() as i64 {
                fail!(
                    ErrorKind::ExceedMaxHeight,
                    "attempted to sign at height {} which is greater than {}",
                    request_height,
                    max_height,
                );
            }
        }

        Ok(())
    }

    /// Handle an incoming request from the validator
    fn handle_request(&'static mut self) -> Result<bool, Error> {
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
                    match self.state.check_update_consensus_state(
                        req_cs.clone(),
                        self.state_syncer.borrow_mut(),
                    ) {
                        Ok(_) => {
                            let signable_bytes = req.to_signable_vec().map_err(|e| {
                                format_err!(
                                    ErrorKind::SigningError,
                                    "cannot get proposal signable bytes: {}",
                                    e
                                )
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
                        Err(e) if e.kind() == &StateErrorKind::DoubleSign => {
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
                        Err(e) => fail!(ErrorKind::SigningError, "failed signing proposal: {}", e),
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
                    match self.state.check_update_consensus_state(
                        req_cs.clone(),
                        self.state_syncer.borrow_mut(),
                    ) {
                        Ok(_) => {
                            let signable_bytes = req.to_signable_vec().map_err(|e| {
                                format_err!(
                                    ErrorKind::SigningError,
                                    "cannot get vote signable bytes: {}",
                                    e
                                )
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
                        Err(e) if e.kind() == &StateErrorKind::DoubleSign => {
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
                        Err(e) => fail!(ErrorKind::SigningError, "failed signing vote: {}", e),
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
            .map_err(|e| format_err!(ErrorKind::IoError, "write response failed: {}", e))?;

        Ok(true)
    }
}
