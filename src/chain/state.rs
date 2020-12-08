mod error;
pub use self::error::{StateError, StateErrorKind};
use anomaly::fail;
use tendermint::{consensus, proposal::SignProposalRequest, vote::SignVoteRequest};

/// State tracking for double signing prevention
pub struct State {
    consensus_state: consensus::State,
}

/// State persistence over sockets or files
pub trait PersistStateSync {
    fn load_state(&mut self) -> Result<State, StateError>;
    fn persist_state(&mut self, new_state: &consensus::State) -> Result<(), StateError>;
}

impl State {
    /// the underlying consensus state
    pub fn consensus_state(&self) -> &consensus::State {
        &self.consensus_state
    }

    fn check_height(&self, new_state: &consensus::State) -> Result<(), StateError> {
        if new_state.height < self.consensus_state.height {
            fail!(
                StateErrorKind::HeightRegression,
                "last height:{} new height:{}",
                self.consensus_state.height,
                new_state.height
            );
        }
        Ok(())
    }

    fn check_round(&self, new_state: &consensus::State) -> Result<(), StateError> {
        if new_state.height == self.consensus_state.height
            && new_state.round < self.consensus_state.round
        {
            fail!(
                StateErrorKind::RoundRegression,
                "round regression at height:{} last round:{} new round:{}",
                new_state.height,
                self.consensus_state.round,
                new_state.round
            )
        }
        Ok(())
    }

    fn check_step(&self, new_state: &consensus::State) -> Result<(), StateError> {
        if new_state.height == self.consensus_state.height
            && new_state.round == self.consensus_state.round
            && new_state.step < self.consensus_state.step
        {
            fail!(
                StateErrorKind::StepRegression,
                "round regression at height:{} round:{} last step:{} new step:{}",
                new_state.height,
                new_state.round,
                self.consensus_state.step,
                new_state.step
            )
        }
        Ok(())
    }

    fn check_block_id(&self, new_state: &consensus::State) -> Result<(), StateError> {
        if new_state.height == self.consensus_state.height
            && new_state.round == self.consensus_state.round
            && (new_state.block_id != self.consensus_state.block_id &&
        // disallow voting for two different block IDs during different steps
        ((new_state.block_id.is_some() && self.consensus_state.block_id.is_some()) ||
        // disallow voting `<nil>` and for a block ID on the same step
        (new_state.step == self.consensus_state.step)))
        {
            fail!(
                StateErrorKind::DoubleSign,
                "Attempting to sign a second proposal at height:{} round:{} step:{} old block id:{} new block {}",
                new_state.height,
                new_state.round,
                new_state.step,
                self.consensus_state.block_id_prefix(),
                new_state.block_id_prefix()
            );
        }
        Ok(())
    }

    /// Check the chain's height, round, and step
    pub fn check_consensus_state(&self, new_state: &consensus::State) -> Result<(), StateError> {
        self.check_height(new_state)?;
        self.check_round(new_state)?;
        self.check_step(new_state)?;
        self.check_block_id(new_state)
    }

    /// Update the state + check
    pub fn check_update_consensus_state(
        &mut self,
        new_state: consensus::State,
        syncer: &mut dyn PersistStateSync,
    ) -> Result<(), StateError> {
        self.check_consensus_state(&new_state)?;
        syncer.persist_state(&new_state)?;
        self.consensus_state = new_state;
        Ok(())
    }
}

impl From<SignProposalRequest> for State {
    fn from(req: SignProposalRequest) -> Self {
        Self {
            consensus_state: consensus::State {
                height: req.proposal.height,
                round: req.proposal.round,
                step: 0,
                block_id: req.proposal.block_id,
            },
        }
    }
}

impl From<SignVoteRequest> for State {
    fn from(req: SignVoteRequest) -> Self {
        Self {
            consensus_state: consensus::State {
                height: req.vote.height,
                round: req.vote.round,
                step: if req.vote.is_precommit() { 2 } else { 1 },
                block_id: req.vote.block_id,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tendermint::block;

    const EXAMPLE_BLOCK_ID: &str =
        "26C0A41F3243C6BCD7AD2DFF8A8D83A71D29D307B5326C227F734A1A512FE47D";

    const EXAMPLE_DOUBLE_SIGN_BLOCK_ID: &str =
        "2470A41F3243C6BCD7AD2DFF8A8D83A71D29D307B5326C227F734A1A512FE47D";

    /// Macro for compactly expressing a consensus state
    macro_rules! state {
        ($height:expr, $round:expr, $step:expr, $block_id:expr) => {
            consensus::State {
                height: block::Height::from($height as u32),
                round: block::Round::from($round as u16),
                step: $step,
                block_id: $block_id,
            }
        };
    }

    /// Macro for compactly representing `Some(block_id)`
    macro_rules! block_id {
        ($id:expr) => {
            Some($id.parse::<block::Id>().unwrap())
        };
    }

    /// Macro for creating a test for a successful state update
    macro_rules! successful_update_test {
        ($name:ident, $old_state:expr, $new_state:expr) => {
            #[test]
            fn $name() {
                State {
                    consensus_state: $old_state,
                }
                .check_consensus_state(&$new_state)
                .unwrap();
            }
        };
    }

    /// Macro for creating a test that expects double sign
    macro_rules! double_sign_test {
        ($name:ident, $old_state:expr, $new_state:expr) => {
            #[test]
            fn $name() {
                let err = State {
                    consensus_state: $old_state,
                }
                .check_consensus_state(&$new_state)
                .expect_err("expected StateErrorKind::DoubleSign but succeeded");

                assert_eq!(err.kind(), &StateErrorKind::DoubleSign)
            }
        };
    }

    successful_update_test!(
        height_update_with_nil_block_id_success,
        state!(1, 1, 0, None),
        state!(2, 0, 0, None)
    );

    successful_update_test!(
        step_update_with_nil_to_some_block_id_success,
        state!(1, 1, 1, None),
        state!(1, 1, 2, block_id!(EXAMPLE_BLOCK_ID))
    );

    successful_update_test!(
        round_update_with_different_block_id_success,
        state!(1, 1, 0, block_id!(EXAMPLE_BLOCK_ID)),
        state!(2, 0, 0, block_id!(EXAMPLE_DOUBLE_SIGN_BLOCK_ID))
    );

    successful_update_test!(
        round_update_with_block_id_and_nil_success,
        state!(1, 1, 0, block_id!(EXAMPLE_BLOCK_ID)),
        state!(2, 0, 0, None)
    );

    successful_update_test!(
        step_update_with_block_id_and_nil_success,
        state!(1, 0, 0, block_id!(EXAMPLE_BLOCK_ID)),
        state!(1, 0, 1, None)
    );

    double_sign_test!(
        step_update_with_different_block_id_double_sign,
        state!(1, 1, 0, block_id!(EXAMPLE_BLOCK_ID)),
        state!(1, 1, 1, block_id!(EXAMPLE_DOUBLE_SIGN_BLOCK_ID))
    );

    double_sign_test!(
        same_hrs_with_different_block_id_double_sign,
        state!(1, 1, 2, None),
        state!(1, 1, 2, block_id!(EXAMPLE_BLOCK_ID))
    );
}
