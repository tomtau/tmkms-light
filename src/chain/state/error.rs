//! Error types regarding chain state (i.e. double signing)
//! Copyright (c) 2018-2021 Iqlusion Inc. (licensed under the Apache License, Version 2.0)
//! Modifications Copyright (c) 2021, Foris Limited (licensed under the Apache License, Version 2.0)

use flex_error::define_error;

define_error! {
    StateError {
        HeightRegressionError {}
        |_| {
            "height regression"
        },

        StepRegressionError {} |_| {
            "step regression"
        },

        RoundRegressionError {} |_| {
            "round regression"
        },
        DoubleSignError{} |_| {
            "double sign detected"
        },
        SyncError{} |_| {
            "error syncing state"
        },
    }
}
