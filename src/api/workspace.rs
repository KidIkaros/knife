//! Stable workspace lifecycle operations for interactive front ends.

use crate::analysis::engine;
use crate::workspace::Session;

/// Re-run recovery after an analyst-approved edit changed analysis inputs.
pub fn reanalyze(session: &mut Session, budget: usize) {
    session.an = engine::analyze(&session.bin, &session.bytes, budget, &session.db);
}
