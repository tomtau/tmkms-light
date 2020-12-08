//! Remote Procedure Calls

use crate::error::{Error, ErrorKind};
use anomaly::{fail, format_err};
use prost::Message as _;
use std::convert::TryFrom;
use std::io::Read;
use tendermint::proposal::{SignProposalRequest, SignedProposalResponse};
use tendermint::public_key::{PubKeyRequest, PublicKey};
use tendermint::vote::{SignVoteRequest, SignedVoteResponse};
use tendermint_p2p::secret_connection::DATA_MAX_SIZE;
use tendermint_proto::{
    crypto::{public_key::Sum as PkSum, PublicKey as RawPublicKey},
    privval::{
        message::Sum, Message as PrivMessage, PingRequest, PingResponse, PubKeyResponse,
        RemoteSignerError, SignedProposalResponse as RawProposalResponse,
        SignedVoteResponse as RawVoteResponse,
    },
};

/// Requests to the KMS
#[derive(Debug)]
pub enum Request {
    /// Sign the given message
    SignProposal(SignProposalRequest),
    SignVote(SignVoteRequest),
    ShowPublicKey(PubKeyRequest),

    // PingRequest is a PrivValidatorSocket message to keep the connection alive.
    ReplyPing(PingRequest),
}

impl Request {
    /// Read a request from the given readable
    pub fn read(conn: &mut impl Read) -> Result<Self, Error> {
        let msg = read_msg(conn)?;

        // Parse Protobuf-encoded request message
        let msg = PrivMessage::decode_length_delimited(msg.as_ref())
            .map_err(|e| format_err!(ErrorKind::ProtocolError, "malformed message packet: {}", e))?
            .sum;

        match msg {
            Some(Sum::SignVoteRequest(req)) => {
                let svr = SignVoteRequest::try_from(req).map_err(|e| {
                    format_err!(
                        ErrorKind::ProtocolError,
                        "sign vote request domain type error: {}",
                        e
                    )
                })?;
                Ok(Request::SignVote(svr))
            }
            Some(Sum::SignProposalRequest(spr)) => {
                let spr = SignProposalRequest::try_from(spr).map_err(|e| {
                    format_err!(
                        ErrorKind::ProtocolError,
                        "sign proposal request domain type error: {}",
                        e
                    )
                })?;
                Ok(Request::SignProposal(spr))
            }
            Some(Sum::PubKeyRequest(pkr)) => {
                let pkr = PubKeyRequest::try_from(pkr).map_err(|e| {
                    format_err!(
                        ErrorKind::ProtocolError,
                        "pubkey request domain type error: {}",
                        e
                    )
                })?;
                Ok(Request::ShowPublicKey(pkr))
            }
            Some(Sum::PingRequest(pr)) => Ok(Request::ReplyPing(pr)),
            _ => fail!(ErrorKind::ProtocolError, "invalid RPC message: {:?}", msg),
        }
    }
}

/// Responses from the KMS
#[derive(Debug)]
pub enum Response {
    /// Signature response
    SignedVote(SignedVoteResponse),
    SignedVoteError(RemoteSignerError),
    SignedProposal(SignedProposalResponse),
    SignedProposalError(RemoteSignerError),
    Ping(PingResponse),
    PublicKey(PublicKey),
    PublicKeyError(RemoteSignerError),
}

/// possible options for double signing error
pub enum DoubleSignErrorType {
    Vote,
    Proposal,
}

/// possible options for chain id error
pub enum ChainIdErrorType {
    Pubkey,
    Vote,
    Proposal,
}

impl Response {
    /// signed vote
    pub fn vote_response(vote: SignVoteRequest, signature: ed25519_dalek::Signature) -> Self {
        let mut vote = vote.vote;
        vote.signature = signature.into();
        Response::SignedVote(SignedVoteResponse {
            vote: Some(vote),
            error: None,
        })
    }

    /// signed proposal
    pub fn proposal_response(
        proposal: SignProposalRequest,
        signature: ed25519_dalek::Signature,
    ) -> Self {
        let mut proposal = proposal.proposal;
        proposal.signature = signature.into();
        Response::SignedProposal(SignedProposalResponse {
            proposal: Some(proposal),
            error: None,
        })
    }

    /// double signing error
    pub fn double_sign(req_type: DoubleSignErrorType, height: i64) -> Self {
        let error = RemoteSignerError {
            code: 2,
            description: format!("double signing requested at height: {}", height),
        };
        match req_type {
            DoubleSignErrorType::Vote => Self::SignedVoteError(error),
            DoubleSignErrorType::Proposal => Self::SignedProposalError(error),
        }
    }

    /// invalid chain id error
    pub fn invalid_chain_id(req_type: ChainIdErrorType, chain_id: &tendermint::chain::Id) -> Self {
        let error = RemoteSignerError {
            code: 1,
            description: format!("invalid chain id: {}", chain_id),
        };
        match req_type {
            ChainIdErrorType::Vote => Self::SignedVoteError(error),
            ChainIdErrorType::Proposal => Self::SignedProposalError(error),
            ChainIdErrorType::Pubkey => Self::PublicKeyError(error),
        }
    }

    /// Encode response to bytes
    pub fn encode(self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();

        let msg = match self {
            Response::SignedVote(resp) => Sum::SignedVoteResponse(resp.into()),
            Response::SignedProposal(resp) => Sum::SignedProposalResponse(resp.into()),
            Response::Ping(_) => Sum::PingResponse(PingResponse {}),
            Response::PublicKey(pk) => {
                let pkr = PubKeyResponse {
                    pub_key: Some(RawPublicKey {
                        sum: Some(PkSum::Ed25519(pk.to_vec())),
                    }),
                    error: None,
                };
                Sum::PubKeyResponse(pkr)
            }
            Response::SignedVoteError(error) => Sum::SignedVoteResponse(RawVoteResponse {
                vote: None,
                error: Some(error),
            }),
            Response::SignedProposalError(error) => {
                Sum::SignedProposalResponse(RawProposalResponse {
                    proposal: None,
                    error: Some(error),
                })
            }
            Response::PublicKeyError(error) => Sum::PubKeyResponse(PubKeyResponse {
                pub_key: None,
                error: Some(error),
            }),
        };

        PrivMessage { sum: Some(msg) }
            .encode_length_delimited(&mut buf)
            .map_err(|e| {
                format_err!(ErrorKind::ProtocolError, "failed to encode response: {}", e)
            })?;
        Ok(buf)
    }
}

/// Read a message from a Secret Connection
// TODO(tarcieri): extract this into Secret Connection
fn read_msg(conn: &mut impl Read) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0; DATA_MAX_SIZE];
    let buf_read = conn
        .read(&mut buf)
        .map_err(|e| format_err!(ErrorKind::IoError, "read msg failed: {}", e))?;
    buf.truncate(buf_read);
    Ok(buf)
}
