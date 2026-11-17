// SPDX-License-Identifier: Apache-2.0
use super::*;
use velarx_proto::workload::EventKind;

/// What a commit asks, decoded from its request.
pub(crate) struct CommitArgs {
    pub container: String,
    /// A short repository is of Docker Hub when `[api] compat_api_enforce_docker_hub` says so
    pub docker_hub: bool,
    pub format: Option<String>,
    pub repo: Option<String>,
    pub tag: Option<String>,
    pub author: Option<String>,
    pub comment: Option<String>,
    pub changes: Vec<String>,
    pub pause: bool,
    pub include_volumes: bool,
    pub squash: bool,
    /// Settings of the new configuration (a Docker container config), as
    /// podman's override config
    pub override_config: Option<Value>,
    /// `sha256` or `sha512` (none: the algorithm of the container's image)
    pub digest: Option<String>,
}

/// The settings of an override configuration that the new image does not
/// take (it takes those of `override_edits`): refused, naming them.
fn refuse_unsupported_config(o: &Value) -> ApiResult<()> {
    super::super::spec::refuse_members(
        o,
        "the configuration",
        &[
            "Hostname",
            "Domainname",
            "AttachStdin",
            "AttachStdout",
            "AttachStderr",
            "Tty",
            "OpenStdin",
            "StdinOnce",
            "Healthcheck",
            "ArgsEscaped",
            "Image",
            "NetworkDisabled",
            "MacAddress",
            "OnBuild",
            "StopTimeout",
            "Shell",
        ],
    )
}

/// The changes of a container as a new image, the progress of its layer
/// told on `progress`: the id of the image.
pub(crate) async fn commit_of(
    state: &AppState,
    args: CommitArgs,
    progress: Option<tokio::sync::mpsc::Sender<velarx_core::services::TransferProgress>>,
) -> ApiResult<String> {
    let container = Some(args.container.as_str())
        .filter(|c| !c.is_empty())
        .ok_or_else(|| ApiError::bad_request("missing the container"))?;
    let rec = super::super::lifecycle::resolve(state, container).await?;
    // the OCI image, the only format
    match args
        .format
        .as_deref()
        .filter(|f| !f.is_empty())
        .unwrap_or("oci")
    {
        "oci" => {}
        f => {
            return Err(match velarx_base::docker::refuse_format_name(f) {
                Err(m) => ApiError::not_implemented(m),
                Ok(()) => ApiError::internal(format!("unrecognized image format {f:?}")),
            })
        }
    }
    if let Some(o) = args.override_config.as_ref().filter(|o| o.is_object()) {
        refuse_unsupported_config(o)?;
    }
    let libpod = !args.docker_hub;
    // (podman's rule, for its command line and its own route: the OCI format
    // has no place for a message; the Docker route takes it)
    if libpod && args.comment.as_deref().is_some_and(|m| !m.is_empty()) {
        return Err(ApiError::internal(
            "messages are only compatible with the docker image format (-f docker)",
        ));
    }
    let name = match (
        args.repo.as_deref().filter(|r| !r.is_empty()),
        args.tag.as_deref().filter(|t| !t.is_empty()),
    ) {
        (Some(repo), Some(tag)) => Some(format!("{}:{tag}", qualify_name(state, libpod, repo))),
        (Some(repo), None) => Some(qualify_name(state, libpod, repo)),
        (None, _) => None,
    };
    let req = velarx_core::services::CommitRequest {
        image: name.clone(),
        author: args.author.filter(|a| !a.is_empty()),
        message: args.comment.filter(|m| !m.is_empty()),
        changes: args.changes,
        pause: args.pause,
        digest: args.digest,
        include_volumes: args.include_volumes,
        squash: args.squash,
        override_config: args.override_config.filter(Value::is_object),
    };
    let id = state
        .container_service
        .commit(&rec.id, &req, progress)
        .await?;
    let image = resolve_image(state, &id).await?;
    let events = &state.podman.events;
    events.emit(Event::new(
        EventKind::Image,
        "commit",
        &image_id(&image),
        name.as_deref().unwrap_or(""),
    ));
    events.emit(
        Event::new(
            EventKind::Container,
            "commit",
            &rec.id,
            rec.name.as_deref().unwrap_or(""),
        )
        .image(&image_id(&image)),
    );
    Ok(image_id(&image))
}

pub(crate) async fn distribution_of(
    state: &AppState,
    name: &str,
    tls_verify: bool,
) -> ApiResult<velarx_proto::workload::RemoteImage> {
    use velarx_proto::workload::{ImagePlatform, RemoteImage};
    if repository_path(name)
        .chars()
        .any(|c| c.is_ascii_uppercase())
    {
        let cause = "repository name must be lowercase";
        return Err(ApiError::bad_request(format!("parsing {name:?}: {cause}")).with_cause(cause));
    }
    let options = PullOptions {
        tls_verify,
        ..PullOptions::default()
    };
    let d = state
        .image_service
        .remote_descriptor(name, &options)
        .await
        .map_err(|e| ApiError::new(e.registry_status(), e.to_string()))?;
    let text = |p: &Value, k: &str| p[k].as_str().unwrap_or_default().to_string();
    let texts = |p: &Value, k: &str| -> Vec<String> {
        p[k].as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok(RemoteImage {
        media_type: d.media_type,
        digest: d.digest.to_string(),
        size: d.size,
        platforms: d
            .platforms
            .iter()
            .map(|p| ImagePlatform {
                architecture: text(p, "architecture"),
                os: text(p, "os"),
                os_version: text(p, "os.version"),
                os_features: texts(p, "os.features"),
                variant: text(p, "variant"),
                features: texts(p, "features"),
            })
            .collect(),
    })
}

/// The layers of the image `name`, the images they are the top layer of,
/// and the images built on it.
pub(crate) async fn tree_of(
    state: &AppState,
    name: &str,
) -> ApiResult<velarx_proto::workload::ImageTreeRecord> {
    use velarx_proto::workload::{ImageTreeChild, ImageTreeLayer, ImageTreeRecord};
    let rec = resolve_image(state, name).await?;
    let v = View::load_required(state, rec).await?;
    let digests: Vec<String> = v.layers.iter().map(|l| l.key.to_string()).collect();
    let mut tops: std::collections::HashMap<String, Vec<String>> = Default::default();
    let mut children = Vec::new();
    for other in state.image_service.list().await? {
        let Some(ov) = View::load(state, other).await? else {
            continue;
        };
        let od: Vec<String> = ov.layers.iter().map(|l| l.key.to_string()).collect();
        if let Some(top) = od.last() {
            tops.entry(top.clone())
                .or_default()
                .extend(ov.names.iter().cloned());
        }
        if od.len() > digests.len() && od.iter().zip(&digests).all(|(a, b)| a == b) {
            children.push(ImageTreeChild {
                id: ov.id.clone(),
                names: ov.names.clone(),
            });
        }
    }
    let mut layers = Vec::new();
    for l in &v.layers {
        // (a lazy layer has no diff id proven: it is known by its key)
        let id = l.diff_id.as_ref().unwrap_or(l.key.digest()).hex();
        layers.push(ImageTreeLayer {
            id,
            // (the size of the uncompressed layer, as podman's)
            size: u64::try_from(super::layer_size(l)?).unwrap_or(0),
            top_of: tops.get(&l.key.to_string()).cloned().unwrap_or_default(),
        });
    }
    Ok(ImageTreeRecord {
        id: v.id.clone(),
        names: v.names.clone(),
        size: u64::try_from(v.size).unwrap_or(0),
        layers,
        children,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_settings_a_commit_cannot_take_are_refused() {
        for (config, name) in [
            (json!({"Hostname": "h"}), "Hostname"),
            (json!({"Domainname": "d"}), "Domainname"),
            (json!({"Tty": true}), "Tty"),
            (json!({"OpenStdin": true}), "OpenStdin"),
            (
                json!({"Healthcheck": {"Test": ["CMD", "true"]}}),
                "Healthcheck",
            ),
            (json!({"StopTimeout": 3}), "StopTimeout"),
            (json!({"OnBuild": ["RUN x"]}), "OnBuild"),
            (json!({"Shell": ["/bin/sh", "-c"]}), "Shell"),
            (json!({"MacAddress": "0a:00:00:00:00:01"}), "MacAddress"),
        ] {
            let e = refuse_unsupported_config(&config).unwrap_err();
            assert_eq!(e.status.as_u16(), 501, "{config}");
            assert!(e.message.contains(name), "{}", e.message);
        }
        // what it takes, and zero values
        refuse_unsupported_config(&json!({
            "User": "u", "Env": ["A=1"], "Cmd": ["x"], "Labels": {"a": "b"},
            "Tty": false, "Hostname": "", "StopTimeout": 0,
        }))
        .unwrap();
    }
}
