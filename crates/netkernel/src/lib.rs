// SPDX-License-Identifier: Apache-2.0
//! The kernel and host side of the container networks.
//!
//! What sets a bridge, its firewall rules and DNS records up and takes them
//! down, what stops pasta, the port forwarder and the namespace of the
//! rootless bridges, and the CNI plugins.  The engine uses it to attach and
//! detach a container; the monitor of a container uses the very same code to
//! release the network when the container ends.  Nothing here reads the
//! database or needs an async runtime.

pub mod bridge;
pub mod cni;
pub mod dns;
pub mod dnsrec;
pub mod error;
pub mod firewall;
pub mod firewalld;
pub mod netlink;
pub mod netns;
pub mod nftnl;
pub mod pasta;
pub mod portfwd;
pub mod rootless_netns;
