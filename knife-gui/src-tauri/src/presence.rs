//! Discord Rich Presence — show what knife is doing in the user's Discord status.
//!
//! Entirely optional and best-effort. It talks only to Discord's local IPC pipe;
//! nothing leaves the machine. If Discord is not running, or no client ID is
//! configured below, every call is a silent no-op — the window never blocks or
//! errors on account of it.

use discord_rich_presence::{
    activity::{Activity, Assets, Timestamps},
    DiscordIpc, DiscordIpcClient,
};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// The Discord Application client ID. To enable presence: create an application
/// at <https://discord.com/developers/applications>, copy its Application ID
/// into this constant, and under Rich Presence -> Art Assets upload the
/// Knife-chan image with the asset key `knifechan`. Left at the placeholder,
/// presence stays disabled.
const CLIENT_ID: &str = "REPLACE_WITH_DISCORD_APP_ID";

static CLIENT: Mutex<Option<DiscordIpcClient>> = Mutex::new(None);
static START: Mutex<i64> = Mutex::new(0);

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn enabled() -> bool {
    CLIENT_ID != "REPLACE_WITH_DISCORD_APP_ID" && !CLIENT_ID.is_empty()
}

/// Build the activity payload. Borrows the two lines for the duration of the
/// `set_activity` call.
fn build<'a>(details: &'a str, state: &'a str) -> Activity<'a> {
    let mut act = Activity::new()
        .assets(
            Assets::new()
                .large_image("knifechan")
                .large_text("knife — find the bug, not just the binary"),
        )
        .timestamps(Timestamps::new().start(*START.lock().unwrap()));
    if !details.is_empty() {
        act = act.details(details);
    }
    if !state.is_empty() {
        act = act.state(state);
    }
    act
}

/// Connect in the background and show an idle status. Never blocks the UI thread
/// and never fails loudly: a missing Discord just leaves presence off.
pub fn init() {
    if !enabled() {
        return;
    }
    *START.lock().unwrap() = now();
    std::thread::spawn(|| {
        if let Ok(mut c) = DiscordIpcClient::new(CLIENT_ID) {
            if c.connect().is_ok() {
                let _ = c.set_activity(build("Idle", "no binary open"));
                *CLIENT.lock().unwrap() = Some(c);
            }
        }
    });
}

/// Set the presence line. `details` is the top line ("Reverse engineering"),
/// `state` the second ("steam_api64.dll · 976 functions"). Reconnects lazily if
/// Discord was started after knife.
#[tauri::command]
pub fn presence_update(details: String, state: String) {
    if !enabled() {
        return;
    }
    let mut guard = CLIENT.lock().unwrap();
    if guard.is_none() {
        if let Ok(mut c) = DiscordIpcClient::new(CLIENT_ID) {
            if c.connect().is_ok() {
                *guard = Some(c);
            }
        }
    }
    if let Some(c) = guard.as_mut() {
        if c.set_activity(build(&details, &state)).is_err() {
            // The pipe dropped (Discord closed); forget the client so the next
            // update reconnects.
            *guard = None;
        }
    }
}
