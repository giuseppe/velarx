// SPDX-License-Identifier: Apache-2.0
//! The types of what the command line asks of the engine through
//! [`super::EngineClient`] (a client of an engine service: the one of the
//! user, or with none running the service a command serves from its own
//! process), and podman's views made of its records.

use super::*;
use serde_json::Value;
use std::io::{Read, Write};
use velarx_proto::workload::TransferProgress;
use velarx_registry::auth::RegistryAccess;

/// What writes the body of a request: an archive, a file, a build context.
pub type Upload<'a> = Box<dyn FnOnce(&mut dyn Write) -> std::io::Result<()> + 'a>;

/// An archive the engine writes as it is read.
pub type Download = Box<dyn Read + Send>;

/// What an operation with progress tells as it goes.
pub type Progress<'a> = &'a mut dyn FnMut(&TransferProgress);

/// The kinds of objects of podman's commands (`inspect`, `exists`, lists).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Container,
    Image,
    Volume,
    Network,
    Pod,
}

/// What a build tells as it goes.
#[derive(Debug, Clone)]
pub enum BuildEvent {
    /// A step starts: its instruction.
    Step(String),
    /// What the build says of a step (standard output, not with `--quiet`).
    Output(String),
    /// What a RUN writes, on its standard output or error.
    Run { stderr: bool, output: String },
    /// The pulls of the bases (standard error, not with `--quiet`).
    Report(String),
    /// The progress of a blob (a base image pulled, the image committed).
    Progress(TransferProgress),
    /// The build for a platform of several starts (`os/arch[/variant]`).
    Platform(String),
}

/// `secret create`.
#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub struct SecretCreate {
    pub name: String,
    pub driver: Option<String>,
    pub driver_opts: std::collections::BTreeMap<String, String>,
    pub labels: std::collections::BTreeMap<String, String>,
    pub replace: bool,
    pub ignore: bool,
}

/// One file of `artifact add`.
#[derive(Debug, Clone, Default)]
pub struct ArtifactAdd {
    pub name: String,
    pub file_name: String,
    pub append: bool,
    pub replace: bool,
    pub artifact_type: Option<String>,
    pub file_type: Option<String>,
    pub annotations: Vec<String>,
    /// `sha256` or `sha512`: the digests of a new artifact
    pub digest: Option<String>,
}

/// `artifact pull` and `artifact push`.
#[derive(Debug, Clone, Default)]
pub struct ArtifactTransfer {
    pub name: String,
    pub tls_verify: bool,
    pub retry: velarx_proto::retry::Retry,
    pub access: RegistryAccess,
}

/// How `cp` puts a tar in a container (podman's `cp --archive`,
/// `--overwrite`).
#[derive(Debug, Clone)]
pub struct ArchivePut {
    /// The new names of the first components of the entries.
    pub rename: std::collections::HashMap<String, String>,
    /// A directory may replace what is not one and the other way round.
    pub overwrite: bool,
    /// The files go to the user of the container (else they keep the owners
    /// of the archive).
    pub chown: bool,
}

impl Default for ArchivePut {
    fn default() -> Self {
        Self {
            rename: Default::default(),
            overwrite: false,
            chown: true,
        }
    }
}

/// `container rm` with podman's options.
#[derive(Debug, Clone, Default)]
pub struct RemoveContainer {
    pub force: bool,
    pub volumes: bool,
    pub ignore: bool,
    pub depend: bool,
    pub timeout: Option<u64>,
}

/// An operation of `velarx manifest` on a list that answers with the
/// digest of the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestOp {
    Create,
    Add,
    Annotate,
    Remove,
}

/// The digests a start of a container is given: an enforced start holds the
/// images of the container to them.
#[derive(Debug, Clone, Copy)]
pub enum Verify<'a> {
    /// `--verify-image` (the REST `verify_image`): none given, a container
    /// made from a digest is refused; given, refused where the digests are
    /// not enforced
    Option(&'a [String]),
    /// The digests in the references of a `run`: nothing where the digests
    /// are not enforced
    Run(&'a [String]),
    /// `start --service`, the start at boot: the digests recorded in the
    /// container
    Service,
}

/// The operations the command line asks that are made of others: a
/// container created and started, podman's views of the records.
impl EngineClient {
    /// Create a container and start it for a client that attaches to its
    /// monitor right away; nothing stays of a container that does not start.
    pub fn create_and_run_container(
        &self,
        req: &CreateContainerRequest,
    ) -> ClientResult<StartedContainer> {
        let id = self.create_container(req)?.id;
        self.start_container_attached(&id, Verify::Run(&req.typed_digests()))
            .inspect_err(|_| {
                let _ = self.remove_container_podman(
                    &id,
                    &RemoveContainer {
                        force: true,
                        volumes: true,
                        ..Default::default()
                    },
                );
            })
    }

    /// podman's list of objects of `kind` (`all`: the containers that do not
    /// run, the intermediate images); `filters` are `KEY=VALUE`.  The
    /// engine's records shaped here (`velarx_shape`).
    pub fn podman_list(&self, kind: Kind, all: bool, filters: &[String]) -> ClientResult<Value> {
        match kind {
            Kind::Container => Ok(Value::Array(
                self.list_containers(all, filters, false, false)?
                    .iter()
                    .map(velarx_shape::container::libpod_list_entry)
                    .collect(),
            )),
            Kind::Volume => Ok(Value::Array(
                self.list_volumes(filters)?
                    .iter()
                    .map(velarx_shape::volume::libpod)
                    .collect(),
            )),
            Kind::Pod => Ok(Value::Array(
                self.list_pods(filters)?
                    .iter()
                    .map(velarx_shape::pod::libpod_list_entry)
                    .collect(),
            )),
            Kind::Image => Ok(Value::Array(
                self.list_images(all, filters)?
                    .iter()
                    .map(velarx_shape::image::libpod_summary)
                    .collect(),
            )),
            Kind::Network => Ok(Value::Array(
                self.list_networks(filters)?
                    .iter()
                    .map(velarx_shape::network::libpod)
                    .collect(),
            )),
        }
    }

    /// podman's inspect of an object.
    pub fn podman_inspect(&self, kind: Kind, name: &str) -> ClientResult<Value> {
        match kind {
            Kind::Container => Ok(velarx_shape::container::libpod_inspect(
                &self.inspect_container(name)?,
            )),
            Kind::Volume => Ok(velarx_shape::volume::libpod(&self.inspect_volume(name)?)),
            Kind::Pod => Ok(velarx_shape::pod::libpod_inspect(&self.inspect_pod(name)?)),
            Kind::Image => Ok(velarx_shape::image::libpod_inspect(
                &self.inspect_image(name)?,
            )),
            Kind::Network => Ok(velarx_shape::network::libpod_inspect(
                &self.inspect_network(name)?,
            )),
        }
    }

    /// podman's inspect of a container with the sizes of its files.
    pub fn podman_inspect_sized(&self, name: &str) -> ClientResult<Value> {
        Ok(velarx_shape::container::libpod_inspect(
            &self.inspect_container_sized(name)?,
        ))
    }
}

/// The digests of `remote_digest`.
#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub struct RemoteDigest {
    pub remote: String,
    pub local: Option<String>,
}
