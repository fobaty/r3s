//! Container lifecycle state machine.
//!
//! Each container has a `Phase` and transitions between phases are governed by
//! the legality table in [`r3s_proto::state::Phase::can_transition_to`]. Transitions
//! live in exactly one function and are table-tested.
//!
//! Phases (from `r3s-proto::state::Phase`):
//! - `Pending` — created but not started
//! - `Creating` — kernel objects being created
//! - `Running` — container is alive
//! - `Paused` — frozen via cgroup
//! - `Stopping` — SIGTERM sent, grace period running
//! - `Exited` — terminated (with or without error)
//! - `Failed` — failed to start or crashed

use r3s_proto::state::Phase;

/// Transition error: the requested transition is illegal from the current phase.
#[derive(Debug, thiserror::Error)]
#[error("illegal transition {from} -> {to}")]
pub struct TransitionError {
    /// The phase the container is currently in.
    pub from: Phase,
    /// The phase the container is trying to transition to.
    pub to: Phase,
}

impl TransitionError {
    /// Check if a transition is legal from `from` to `to`.
    ///
    /// This delegates to the canonical transition table in `Phase::can_transition_to`.
    pub fn can_transition(from: Phase, to: Phase) -> Result<(), TransitionError> {
        if from.can_transition_to(to) {
            Ok(())
        } else {
            Err(TransitionError { from, to })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r3s_proto::state::Phase;

    #[test]
    fn valid_transitions() {
        assert!(TransitionError::can_transition(Phase::Pending, Phase::Creating).is_ok());
        assert!(TransitionError::can_transition(Phase::Creating, Phase::Running).is_ok());
        assert!(TransitionError::can_transition(Phase::Running, Phase::Stopping).is_ok());
        assert!(TransitionError::can_transition(Phase::Stopping, Phase::Exited).is_ok());
        assert!(TransitionError::can_transition(Phase::Pending, Phase::Failed).is_ok());
    }

    #[test]
    fn invalid_transitions() {
        assert!(TransitionError::can_transition(Phase::Pending, Phase::Running).is_err());
        assert!(TransitionError::can_transition(Phase::Running, Phase::Pending).is_err());
        assert!(TransitionError::can_transition(Phase::Exited, Phase::Running).is_err());
    }
}
