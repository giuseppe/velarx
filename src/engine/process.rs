// SPDX-License-Identifier: Apache-2.0
//! The engine of a command, in the process of the command, and the engine
//! service it is asked through.  Started once (by the command or by `run`),
//! it lives until the command is done.

use super::{signals, Local};
use crate::client::EngineClient;
use crate::daemon::Role;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use velarx_config::Config;

/// The engine of the command.
static ENGINE: OnceLock<Local> = OnceLock::new();

/// What the service of the engine of this command is served from, until the
/// command is done.
struct Service {
    server: Mutex<crate::engine_service::Server>,
    client: EngineClient,
}

static SERVICE: OnceLock<Service> = OnceLock::new();

/// The engine of the command, if it was started.
pub fn started() -> Option<&'static Local> {
    ENGINE.get()
}

/// Start the engine of the command with `config` (read from `config_path`),
/// as `role` says.
pub fn start(
    config: Arc<Config>,
    config_path: &Path,
    role: &Role,
) -> anyhow::Result<&'static Local> {
    let started = Local::start(config, config_path, role)?;
    Ok(ENGINE.get_or_init(|| started))
}

/// The client of the service of the engine of this command, served on the
/// first ask.  The signals that end the command are taken for its length: the
/// first closes the connections (the calls under way stop as they do for a
/// client that went), waits for the service to be idle and ends the command.
pub fn service(local: &'static Local) -> anyhow::Result<EngineClient> {
    if let Some(s) = SERVICE.get() {
        return Ok(s.client.clone());
    }
    let (server, client) = local.serve()?;
    let _ = SERVICE.set(Service {
        server: Mutex::new(server),
        client: client.clone(),
    });
    signals::end_on_signals(end)?;
    Ok(client)
}

/// Let the engine of this command go: the service of its process stops and
/// is waited for, what it leaves running goes to a server, the cleanups under
/// way are waited for.  Once: the thread of the command at its end and the
/// thread a signal woke can both come here; the second waits for the first.
fn end() {
    static ENDED: std::sync::Once = std::sync::Once::new();
    ENDED.call_once(|| {
        let Some(engine) = ENGINE.get() else { return };
        if let Some(s) = SERVICE.get() {
            // The builds first, as the engine service does at its end: a
            // build runs on the thread of the service, and stopping the
            // service drops it there, its RUN container left running.
            engine.stop_builds();
            let activity = {
                let mut server = s.server.lock().unwrap_or_else(|e| e.into_inner());
                server.stop();
                server.activity.clone()
            };
            engine.drain(&activity);
        }
        engine.finish();
    });
}

/// [`end`], at the end of the command; a command a signal ended is ended by
/// the thread that took the signal.
pub fn finish() {
    signals::wait_if_ended();
    end();
}
