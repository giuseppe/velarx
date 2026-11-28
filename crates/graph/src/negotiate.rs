// SPDX-License-Identifier: Apache-2.0
//! What the engine asks of a driver before it does it: an option the driver's
//! [`Capabilities`] lack is refused up front, with the driver named and what
//! to do, never replaced by another behaviour without a word.

use crate::{Capabilities, DriverError, DriverErrorKind, IdmapWay, Prefs, VerityEnforcement};

/// What is asked.
#[derive(Debug, Clone, Default)]
pub struct Ask {
    /// A lazy pull or a container of an image whose files are partly missing.
    pub lazy: bool,
    /// The digests of what runs are enforced at run time: `[storage]
    /// fsverity_require`, `composefs_digests = "require"`, or the
    /// container's `--security-opt verity=enforce`.
    pub verity_enforced: bool,
    /// `[storage] fsverity_best_effort`: a check at pull is enough.
    pub verity_best_effort: bool,
    /// `[storage] additional_image_stores` lists read-only stores of the same
    /// driver.
    pub shared_stores: bool,
    /// The engine runs as an unprivileged user.
    pub unprivileged: bool,
    /// A container with a user namespace of its own: its root file system
    /// (and its image mounts) must show its ids.
    pub userns: bool,
    /// A limit on the writable layer (`--storage-opt size=`).
    pub size_limit: bool,
    /// An image mounted in a container (`--mount type=image`).
    pub image_volumes: bool,
}

impl Capabilities {
    /// Whether the digests are checked while a container runs.
    pub fn verity_at_run_time(&self) -> bool {
        self.verity
            .iter()
            .any(|v| matches!(v, VerityEnforcement::OnOpen | VerityEnforcement::Kernel))
    }

    /// The most layers an image may have (the pull refuses more, the mount
    /// too): the driver's `max_layers`, less the data-only layers the engine
    /// adds below the image: the objects of each of the `stores` and, for an
    /// image that is not all in the store (`lazy`), the directory of the
    /// files fetched for each layer, so half of what is left.
    pub fn max_image_layers(&self, stores: usize, lazy: bool) -> Option<usize> {
        self.max_layers.map(|m| {
            let left = m.saturating_sub(stores);
            match lazy {
                true => left / 2,
                false => left,
            }
        })
    }

    /// What the driver can do, as one line for `velarx info`: the options
    /// that [`refuse`](Self::refuse) turns down for a driver without them.
    pub fn summary(&self) -> String {
        let yes = |b: bool| if b { "yes" } else { "no" };
        let verity = if self.verity_at_run_time() {
            "at run time"
        } else {
            "at pull only"
        };
        let layers = self
            .max_layers
            .map_or_else(|| "no limit".to_string(), |m| m.to_string());
        format!(
            "lazy {}, rootless {}, fs-verity {verity}, shared stores {}, image volumes {}, user namespaces {}, size limit {}, layers {layers}",
            yes(self.lazy),
            yes(self.rootless),
            yes(self.shared_stores),
            yes(self.volume.is_some()),
            yes(!self.root.idmap.is_empty()),
            yes(self.writable_size_limit),
        )
    }

    /// An error naming `driver` for what `ask` wants and the capabilities
    /// lack.
    pub fn refuse(&self, driver: &str, ask: &Ask) -> Result<(), DriverError> {
        let no = |why: String| Err(DriverError::of(driver, DriverErrorKind::Unsupported, why));
        if ask.lazy && !self.lazy {
            return no(format!(
                "the storage driver {driver} copies whole layers and has no images whose files are partly missing: pull without --lazy"
            ));
        }
        if ask.verity_enforced && !self.verity_at_run_time() && !ask.verity_best_effort {
            return no(format!(
                "the storage driver {driver} checks fs-verity only when a layer is pulled, so its digests cannot be enforced while a container runs (`[storage] fsverity_require`, `composefs_digests = \"require\"`, `--security-opt verity=enforce`): set `[storage] fsverity_best_effort = true` to accept the check at pull, or use the composefs driver"
            ));
        }
        if ask.shared_stores && !self.shared_stores {
            return no(format!(
                "the storage driver {driver} does not use read-only image stores (`[storage] additional_image_stores`): the images of another store have no table of contents here; remove them from the configuration, or use the composefs driver"
            ));
        }
        if ask.unprivileged && !self.rootless {
            return no(format!(
                "the storage driver {driver} does not work for an unprivileged user: run velarx as root, or use the composefs driver"
            ));
        }
        if ask.image_volumes && self.volume.is_none() {
            return no(format!(
                "the storage driver {driver} does not mount images in containers (--mount type=image): use the composefs driver, or copy the files in with --volume"
            ));
        }
        if ask.userns {
            // (a monitor mount needs root of the initial user namespace, so
            // for an unprivileged engine it is no way)
            let usable = |ways: Prefs<IdmapWay>| {
                ways.iter()
                    .any(|w| !(ask.unprivileged && w == IdmapWay::MonitorMount))
            };
            if !usable(self.root.idmap) {
                return no(format!(
                    "the storage driver {driver} cannot show the ids of a container with a user namespace of its own{}: run the container without one (--userns=host), or use the composefs driver",
                    if ask.unprivileged && !self.root.idmap.is_empty() {
                        " for an unprivileged user (it needs root to map them on the mount)"
                    } else {
                        ""
                    }
                ));
            }
            if ask.image_volumes && !self.volume.is_some_and(|v| usable(v.idmap)) {
                return no(format!(
                    "the storage driver {driver} cannot show the ids of an image mounted in a container with a user namespace of its own: run the container without one (--userns=host), or use the composefs driver"
                ));
            }
        }
        if ask.size_limit && !self.writable_size_limit {
            return no(format!(
                "the storage driver {driver} has no quota of the writable layer of a container (--storage-opt size=): leave the limit out, or use a driver that has one"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MountCaps;

    fn caps(verity: &[VerityEnforcement]) -> Capabilities {
        Capabilities {
            lazy: false,
            serve_content: false,
            rootless: true,
            verity: Prefs::new(verity),
            shared_stores: false,
            layer_chain: false,
            max_layers: Some(10),
            overlay_upper: false,
            writable_size_limit: false,
            root: MountCaps {
                idmap: Prefs::new(&[IdmapWay::AtCopy]),
            },
            volume: None,
        }
    }

    fn why(c: &Capabilities, ask: Ask) -> Option<String> {
        c.refuse("d", &ask).err().map(|e| {
            assert!(matches!(e.kind, DriverErrorKind::Unsupported));
            assert_eq!(e.driver, "d");
            e.message().to_string()
        })
    }

    #[test]
    fn what_a_driver_lacks_is_refused_up_front_with_what_to_do() {
        let pull_only = caps(&[VerityEnforcement::PullOnly]);
        assert_eq!(why(&pull_only, Ask::default()), None);
        assert!(why(
            &pull_only,
            Ask {
                lazy: true,
                ..Default::default()
            }
        )
        .unwrap()
        .contains("pull without --lazy"));
        // enforced digests: an error, unless best effort is said
        let enforced = Ask {
            verity_enforced: true,
            ..Default::default()
        };
        assert!(why(&pull_only, enforced.clone())
            .unwrap()
            .contains("fsverity_best_effort = true"));
        assert_eq!(
            why(
                &pull_only,
                Ask {
                    verity_best_effort: true,
                    ..enforced.clone()
                }
            ),
            None
        );
        // a driver that checks at run time takes it, with or without
        let at_run = caps(&[VerityEnforcement::Kernel, VerityEnforcement::OnOpen]);
        assert_eq!(why(&at_run, enforced), None);
        assert!(why(
            &pull_only,
            Ask {
                shared_stores: true,
                ..Default::default()
            }
        )
        .unwrap()
        .contains("additional_image_stores"));
        // a driver that has what is asked takes it
        let mut all = caps(&[VerityEnforcement::OnOpen]);
        (all.lazy, all.shared_stores) = (true, true);
        assert_eq!(
            why(
                &all,
                Ask {
                    lazy: true,
                    verity_enforced: true,
                    shared_stores: true,
                    ..Default::default()
                }
            ),
            None
        );
        // the layers: the driver's maximum less what the engine adds below
        assert_eq!(pull_only.max_image_layers(2, false), Some(8));
        assert_eq!(pull_only.max_image_layers(1, false), Some(9));
        // (a lazy image: a directory of fetched files for each layer)
        assert_eq!(pull_only.max_image_layers(1, true), Some(4));
        assert_eq!(pull_only.max_image_layers(2, true), Some(4));
        let mut unlimited = caps(&[VerityEnforcement::PullOnly]);
        unlimited.max_layers = None;
        assert_eq!(unlimited.max_image_layers(2, true), None);
    }

    /// Each option the driver lacks is refused up front, naming the driver
    /// and what to do; one it has is taken.
    #[test]
    fn the_options_of_a_container_are_refused_up_front() {
        let mut c = caps(&[VerityEnforcement::PullOnly]);
        let ask = |f: fn(&mut Ask)| {
            let mut a = Ask::default();
            f(&mut a);
            a
        };
        // image mounts: a driver without a volume purpose refuses them
        let m = why(&c, ask(|a| a.image_volumes = true)).unwrap();
        assert!(
            m.contains("--mount type=image") && m.contains("--volume"),
            "{m}"
        );
        c.volume = Some(MountCaps {
            idmap: Prefs::new(&[IdmapWay::AtCopy]),
        });
        assert_eq!(why(&c, ask(|a| a.image_volumes = true)), None);
        // a user namespace: needs a way to show the ids
        assert_eq!(why(&c, ask(|a| a.userns = true)), None);
        let mut none = c.clone();
        none.root.idmap = Prefs::NONE;
        assert!(why(&none, ask(|a| a.userns = true))
            .unwrap()
            .contains("--userns=host"));
        // (and a way for the image mounts too when there are some)
        let mut vol_none = c.clone();
        vol_none.volume = Some(MountCaps { idmap: Prefs::NONE });
        assert!(why(
            &vol_none,
            ask(|a| {
                a.userns = true;
                a.image_volumes = true
            })
        )
        .unwrap()
        .contains("image mounted"));
        assert_eq!(why(&vol_none, ask(|a| a.userns = true)), None);
        // a way that needs root is no way for an unprivileged engine
        let mut monitor = c.clone();
        monitor.root.idmap = Prefs::new(&[IdmapWay::MonitorMount]);
        assert_eq!(why(&monitor, ask(|a| a.userns = true)), None);
        assert!(why(
            &monitor,
            ask(|a| {
                a.userns = true;
                a.unprivileged = true
            })
        )
        .unwrap()
        .contains("needs root"));
        monitor.root.idmap = Prefs::new(&[IdmapWay::MonitorMount, IdmapWay::AtCopy]);
        assert_eq!(
            why(
                &monitor,
                ask(|a| {
                    a.userns = true;
                    a.unprivileged = true
                })
            ),
            None
        );
        // an unprivileged engine
        c.rootless = false;
        assert!(why(&c, ask(|a| a.unprivileged = true))
            .unwrap()
            .contains("unprivileged"));
        c.rootless = true;
        assert_eq!(why(&c, ask(|a| a.unprivileged = true)), None);
        // a quota
        assert!(why(&c, ask(|a| a.size_limit = true))
            .unwrap()
            .contains("--storage-opt size="));
        c.writable_size_limit = true;
        assert_eq!(why(&c, ask(|a| a.size_limit = true)), None);
    }
}
