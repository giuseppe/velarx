// SPDX-License-Identifier: Apache-2.0
//! The release of the rootless network namespace when no bridge in it has a
//! port.

use crate::teardown::Detach;
use std::os::fd::AsFd;
use tracing::{debug, warn};
use velarx_netkernel::bridge;
use velarx_netkernel::error::NetworkResult;
use velarx_netkernel::pasta;
use velarx_netkernel::rootless_netns::Found;

/// The processes of the rootless namespace as they are found beforehand: a
/// thread that Landlock confines cannot read the `/proc` entries of the
/// processes outside its domain (`ptrace` access), so what names them (the
/// command line of its pasta, the namespace of its holder) is found by the
/// caller before it confines ([`Detach::hold`]) and used after.
pub struct Held {
    pasta: pasta::Found,
    /// The namespace, open: none when nothing keeps it
    pub(crate) ns: Option<Found>,
    /// The namespace the database recorded when nothing kept it: the
    /// release goes on only while the record is the same
    record: Option<velarx_nsid::NamespaceId>,
}

impl Detach {
    /// Find the pasta and the namespace of the rootless bridges.
    pub fn hold(&self) -> NetworkResult<Held> {
        let pid_file = velarx_netkernel::rootless_netns::pasta_pid_file(&self.run);
        let pasta = pasta::find(&pid_file, true);
        let ns = velarx_netkernel::rootless_netns::locate(
            &self.run,
            &self.db,
            velarx_nsid::tree::members,
        )?;
        let record = match &ns {
            Some(_) => None,
            None => velarx_netkernel::rootless_netns::read_record(&self.db)?.map(|r| r.id),
        };
        Ok(Held { pasta, ns, record })
    }

    /// Whether what [`Self::hold`] found is still what the database records,
    /// under the locks of [`Self::release_unused`]: another release may have
    /// given the namespace up since, and a setup made a new one, which is not
    /// this release's to stop.
    fn still_recorded(&self, held: &Held) -> NetworkResult<bool> {
        let now = velarx_netkernel::rootless_netns::read_record(&self.db)?.map(|r| r.id);
        Ok(match (&held.ns, now) {
            (Some(found), Some(now)) => {
                velarx_nsid::id_of(found.ns.as_fd()).is_ok_and(|id| id.is_same(&now))
            }
            (Some(_), None) => false,
            (None, now) => match (now, &held.record) {
                (None, None) => true,
                (Some(now), Some(then)) => now.is_same(then),
                _ => false,
            },
        })
    }

    /// Give the rootless network namespace and its pasta up when no bridge
    /// in it has a port (podman keeps its rootless-netns while it is used):
    /// its bridges and its table go with it.  What a holder or a pasta left
    /// behind a namespace that is gone is removed too.  It runs when a bridge
    /// network is released or removed; `system prune` and `system check
    /// --repair` run it for the holder whose last container's release never
    /// ran.  `on_stop_pasta` runs before the pasta is stopped: the engine
    /// ends the watch of it there, else it would start the pasta stopped here
    /// again.
    pub fn release_if_unused(&self, on_stop_pasta: &dyn Fn()) {
        self.release_rootless(None, on_stop_pasta);
    }

    /// [`Self::release_if_unused`] with what [`Self::hold`] found before the
    /// caller confined itself (it is checked against the record under the
    /// locks).
    pub fn release_held(&self, held: Held, on_stop_pasta: &dyn Fn()) {
        self.release_rootless(Some(held), on_stop_pasta);
    }

    fn release_rootless(&self, held: Option<Held>, on_stop_pasta: &dyn Fn()) {
        if !self.rootless || !self.rootless_netns {
            return;
        }
        match self.release_unused(held, on_stop_pasta) {
            Ok(true) => debug!("the rootless network namespace is unused: released"),
            Ok(false) => {}
            Err(e) => warn!("release the rootless network namespace: {e}"),
        }
    }

    fn release_unused(&self, held: Option<Held>, on_stop_pasta: &dyn Fn()) -> NetworkResult<bool> {
        let run = &self.run;
        let pid_file = velarx_netkernel::rootless_netns::pasta_pid_file(run);
        // (after the setups under way: their bridges keep the namespace)
        let _users = velarx_netkernel::rootless_netns::release_lock(run)?;
        let _lock = bridge::lock_networks(run)?;
        // (found under the locks; else what was found before is checked to be
        // what is recorded now)
        let held = match held {
            None => self.hold()?,
            Some(held) if self.still_recorded(&held)? => held,
            Some(_) => return Ok(false),
        };
        let Held { pasta, ns, .. } = held;
        let stop_pasta = || {
            on_stop_pasta();
            pasta::stop_found(&pid_file, pasta, true)
        };
        let Some(found) = ns else {
            // no process is in the namespace any more: what is left of it
            // goes
            stop_pasta();
            velarx_netkernel::rootless_netns::stop(&self.db);
            return Ok(false);
        };
        // (a bridge stays after its last container, until its network goes:
        // here the namespace takes it, and the table, with it)
        let used = bridge::in_netns(found.ns.as_fd(), || {
            let links = velarx_netkernel::netlink::Netlink::open()?.links()?;
            Ok(links.iter().any(|b| {
                b.kind == "bridge"
                    && b.alias.starts_with(bridge::OWNER_PREFIX)
                    && links.iter().any(|l| l.master == b.index)
            }))
        })?;
        if used {
            return Ok(false);
        }
        stop_pasta();
        velarx_netkernel::rootless_netns::stop(&self.db);
        Ok(true)
    }
}
