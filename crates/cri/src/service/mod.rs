// SPDX-License-Identifier: Apache-2.0
//! The CRI services: each RPC is a mapping to calls of `Engine`.

mod convert;
mod image;
mod runtime;

use crate::engine::{Engine, EngineError};
use crate::stream::Sessions;
use std::sync::{Arc, Mutex};
use tonic::Status;

pub use convert::{signal_name, ts_secs_to_ns};

/// The version of the CRI API this implements.
pub const CRI_API_VERSION: &str = "v1";
/// The version the kubelet is told (`VersionResponse.version`).
pub const KUBE_RUNTIME_API: &str = "0.1.0";

pub struct Cri<E: Engine> {
    pub(crate) engine: Arc<E>,
    pub(crate) streams: Arc<Sessions>,
    /// `host:port` the streaming server listens on
    pub(crate) stream_addr: String,
    /// The network of the pods, as the engine names it (`cni:`, `cni:NAME`);
    /// empty: the engine's default
    pub(crate) pod_network: String,
    /// The image of the infra container of every sandbox (containerd's
    /// `sandbox_image`); empty: the engine's `infra_image`
    pub(crate) sandbox_image: String,
    /// The pod CIDR the kubelet gave with `UpdateRuntimeConfig`: the subnets
    /// (one for each address family) of the pods of this node
    pub(crate) pod_cidr: Mutex<Vec<String>>,
    /// The cgroup controllers of the containers of the engine, once asked
    pub(crate) controllers: tokio::sync::OnceCell<Vec<String>>,
    /// The infra image of the engine (its configuration), once asked
    pub(crate) engine_infra_image: tokio::sync::OnceCell<String>,
}

impl<E: Engine> Cri<E> {
    pub fn new(engine: Arc<E>, streams: Arc<Sessions>, stream_addr: String) -> Self {
        Self {
            engine,
            streams,
            stream_addr,
            pod_network: String::new(),
            sandbox_image: String::new(),
            pod_cidr: Mutex::default(),
            controllers: tokio::sync::OnceCell::new(),
            engine_infra_image: tokio::sync::OnceCell::new(),
        }
    }

    /// Whether the cgroups the engine makes for the containers have the
    /// controller `name` (the engine's are asked once).
    pub(crate) async fn has_controller(&self, name: &str) -> Result<bool, tonic::Status> {
        let list = self
            .controllers
            .get_or_try_init(|| async {
                self.engine
                    .version()
                    .await
                    .map(|v| v.cgroup_controllers)
                    .map_err(status)
            })
            .await?;
        Ok(list.iter().any(|c| c == name))
    }

    /// The pods are on the network NETWORK of the engine (`cni:` or
    /// `cni:NAME` for CNI, whose configurations and plugins are the engine's).
    pub fn with_pod_network(mut self, network: &str) -> Self {
        self.pod_network = network.to_string();
        self
    }

    /// Every sandbox is made with the infra image IMAGE (the engine pulls it
    /// when it is missing).
    pub fn with_sandbox_image(mut self, image: &str) -> Self {
        self.sandbox_image = image.to_string();
        self
    }

    pub(crate) fn pod_cidr(&self) -> Vec<String> {
        self.pod_cidr
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether the network of the pods can be used: a CNI network needs a
    /// configuration whose plugins say they are ready (STATUS; the kubelet
    /// makes the node not ready until then).
    pub(crate) async fn network_ready(&self) -> Result<(), String> {
        if !self.pod_network.starts_with("cni:") {
            return Ok(());
        }
        match self.engine.network_status(&self.pod_network).await {
            Ok(s) if s.ready => Ok(()),
            Ok(s) => Err(s.message),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn runtime_server(
        self: &Arc<Self>,
    ) -> crate::api::runtime_service_server::RuntimeServiceServer<Self> {
        crate::api::runtime_service_server::RuntimeServiceServer::from_arc(self.clone())
            .max_decoding_message_size(16 << 20)
            .max_encoding_message_size(16 << 20)
    }

    pub fn image_server(
        self: &Arc<Self>,
    ) -> crate::api::image_service_server::ImageServiceServer<Self> {
        crate::api::image_service_server::ImageServiceServer::from_arc(self.clone())
            .max_decoding_message_size(16 << 20)
            .max_encoding_message_size(16 << 20)
    }
}

impl From<crate::meta::MetaError> for Status {
    fn from(e: crate::meta::MetaError) -> Status {
        Status::internal(e.to_string())
    }
}

pub(crate) fn status(e: EngineError) -> Status {
    match e {
        EngineError::NotFound(m) => Status::not_found(m),
        EngineError::Conflict(m) => Status::already_exists(m),
        EngineError::Invalid(m) => Status::invalid_argument(m),
        EngineError::Unsupported(m) => Status::unimplemented(format!("velarx: {m}")),
        EngineError::Precondition(m) => Status::failed_precondition(m),
        EngineError::Denied(m) => Status::permission_denied(m),
        EngineError::Unauthenticated(m) => Status::unauthenticated(m),
        EngineError::Exhausted(m) => Status::resource_exhausted(m),
        EngineError::Unavailable(m) => Status::unavailable(m),
        EngineError::DataLoss(m) => Status::data_loss(m),
        EngineError::DeadlineExceeded(m) => Status::deadline_exceeded(m),
        EngineError::Other(m) => Status::internal(m),
    }
}

pub(crate) type Stream<T> =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<T, Status>> + Send + 'static>>;

/// A stream of one answer.
pub(crate) fn once<T: Send + 'static>(v: T) -> Stream<T> {
    Box::pin(futures::stream::once(async move { Ok(v) }))
}
