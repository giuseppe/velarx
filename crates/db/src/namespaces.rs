// SPDX-License-Identifier: Apache-2.0
//! The namespaces of a boot in the store's database.
//!
//! `namespaces` and `holders` are keyed by the boot (`boot_id`): the rows of
//! another boot describe namespaces that are gone, are never read and are
//! forgotten by the first write of the next boot.  The SQL on them is in
//! `velarx_nsid::store`; what is here is the schema.  The processes that join
//! the namespaces of the rootless user write them before they have a thread,
//! with [`crate::volatile::open`]: they need no durability.

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS namespaces (
    boot_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('user', 'mnt', 'net', 'pid', 'ipc', 'uts', 'cgroup', 'time')),
    dev INTEGER NOT NULL,
    ino INTEGER NOT NULL,
    handle_type INTEGER,
    mount_id INTEGER,
    handle BLOB,
    PRIMARY KEY (boot_id, scope, kind)
);

CREATE TABLE IF NOT EXISTS holders (
    boot_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    pid INTEGER NOT NULL,
    start INTEGER NOT NULL,
    role TEXT NOT NULL,
    PRIMARY KEY (boot_id, scope, pid, start)
);
";
