// SPDX-License-Identifier: Apache-2.0
//! The typed records and specs of [`velarx_proto::workload`] that are still
//! made of the engine's podman shaped documents (images, stats) and into
//! the generators its handlers take: what `ImageInspect`, `ImageList` and
//! the rest of the calls the CRI makes do (the containers and pods are
//! records of their own, `cinfo`, `pods`).

use super::error::{ApiError, ApiResult};
use super::{lifecycle, system};
use crate::api::AppState;
use serde_json::Value;
use velarx_proto::engine::{NetworkStatus, RuntimeHandlerSupport, RuntimeInfo, StorageUsage};

/// The `config.json` of the bundle of a container, as the runtime was given it.
pub(crate) async fn runtime_spec(state: &AppState, name: &str) -> ApiResult<String> {
    let rec = lifecycle::resolve(state, name).await?;
    let path = state
        .container_service
        .bundle_dir(&rec.id)
        .join("config.json");
    tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => ApiError::invalid_state(format!(
                "container {} has no runtime configuration yet",
                rec.id
            )),
            _ => ApiError::internal(format!("{}: {e}", path.display())),
        })
}

pub(crate) async fn storage_usage(state: &AppState) -> ApiResult<StorageUsage> {
    let usage = system::disk_usage(state, false).await?;
    let store = system::system_record(state).await?.store;
    Ok(StorageUsage {
        mountpoint: store.graph_root,
        images_bytes: usage.images_size,
        containers_bytes: usage.containers.iter().map(|c| c.rw_size).sum(),
        inodes_used: store.graph_root_inodes_used,
    })
}

/// What a runtime can do for the CRI, by the `features` it prints (as
/// containerd reads them): recursive read-only mounts are `rro` among its
/// mount options; user namespaces need the `user` namespace and ID-mapped
/// mounts (`idmap` among the mount options, or `linux.mountExtensions.idmap`).  A
/// runtime that prints none (runsc, an old youki) can do neither.
fn handler_support(name: &str, features: &str) -> RuntimeHandlerSupport {
    let doc: Value = serde_json::from_str(features).unwrap_or(Value::Null);
    let has =
        |list: &Value, what: &str| list.as_array().is_some_and(|l| l.iter().any(|v| v == what));
    let options = &doc["mountOptions"];
    let idmap =
        has(options, "idmap") || doc["linux"]["mountExtensions"]["idmap"]["enabled"] == true;
    RuntimeHandlerSupport {
        name: name.into(),
        recursive_read_only_mounts: has(options, "rro"),
        user_namespaces: has(&doc["linux"]["namespaces"], "user") && idmap,
    }
}

pub(crate) async fn runtime_info(state: &AppState) -> ApiResult<RuntimeInfo> {
    let s = system::system_record(state).await?;
    let handler_support = std::iter::once(handler_support(
        &s.host.oci_runtime.name,
        &s.host.oci_runtime.features,
    ))
    .chain(
        s.host
            .runtimes
            .iter()
            .map(|r| handler_support(&r.name, &r.features)),
    )
    .collect();
    Ok(RuntimeInfo {
        name: "velarx".into(),
        version: s.version.version,
        api_version: velarx_shape::system::COMPAT_VERSION.into(),
        cgroup_manager: s.host.cgroup_manager,
        oci_runtime: s.host.oci_runtime.name,
        handler_support,
        oci_runtimes: s.host.runtimes.into_iter().map(|r| r.name).collect(),
        cgroup_controllers: s.host.cgroup_controllers,
        infra_image: velarx_core::services::infra_image_name([state
            .config
            .containers
            .infra_image
            .as_deref()]),
    })
}

/// What the plugins of the CNI network `network` (`cni:NAME`) say of it.
pub(crate) async fn network_status(state: &AppState, network: &str) -> ApiResult<NetworkStatus> {
    let name = network.strip_prefix("cni:").ok_or_else(|| {
        ApiError::bad_request(format!("{network} is not a CNI network (`cni:NAME`)"))
    })?;
    let v = state.network_service.engine().cni_status(name).await?;
    Ok(NetworkStatus {
        ready: v["ready"].as_bool().unwrap_or(false),
        message: v["message"].as_str().unwrap_or("").to_string(),
    })
}

#[cfg(test)]
mod handler_tests {
    use super::*;

    #[test]
    fn the_features_of_a_runtime_say_what_its_handler_can_do() {
        let both =
            r#"{"mountOptions":["ro","rro","idmap"],"linux":{"namespaces":["mount","user"]}}"#;
        let h = handler_support("crun", both);
        assert_eq!(h.name, "crun");
        assert!(h.recursive_read_only_mounts && h.user_namespaces);
        // runc: the extension of `linux` says idmap, a mount option does not
        let ext = r#"{"mountOptions":["ro"],"linux":{"namespaces":["user"],"mountExtensions":{"idmap":{"enabled":true}}}}"#;
        let h = handler_support("runc", ext);
        assert!(!h.recursive_read_only_mounts && h.user_namespaces);
        // a user namespace without ID-mapped mounts is not enough
        let noidmap = r#"{"mountOptions":["rro"],"linux":{"namespaces":["user"]}}"#;
        let h = handler_support("runc", noidmap);
        assert!(h.recursive_read_only_mounts && !h.user_namespaces);
        // no features, no support
        assert_eq!(
            handler_support("runsc", ""),
            RuntimeHandlerSupport {
                name: "runsc".into(),
                ..Default::default()
            }
        );
    }
}
