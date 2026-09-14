//! Persistence lifecycle operations exposed to front ends.

use crate::workspace::Session;
use anyhow::Result;

/// Persist approved analyst facts and staged patches.
///
/// Analysis caches are separate from this user-owned annotation store.
pub fn save_analyst_state(session: &Session) -> Result<()> {
    session.db.save()
}
