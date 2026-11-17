// SPDX-License-Identifier: Apache-2.0
//! `generate systemd` (`GET /generate/{name}/systemd`), and the `kube`
//! routes: the engine has no kube commands, the answer to them says where
//! they are.

use super::call::Call;
use super::error::{ApiError, ApiResult};
use super::reply;
use super::{route, Route};
use crate::engine::engine_call;
use serde_json::json;
use velarx_proto::engine::SystemdSpec;

/// The values of a parameter that may come several times, the empty ones
/// left out.
fn all(call: &Call, name: &str) -> Vec<String> {
    call.q_all(name)
        .into_iter()
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .collect()
}

/// `kube play`, `kube down`, `kube apply` and `generate kube` are the command
/// `velarx-kube`'s, not the engine's: no route of the API serves them, by
/// design (the API does not run `velarx-kube`).
async fn kube(_call: Call) -> ApiResult {
    Err(ApiError::not_implemented(
        "kube play, down, apply and generate are not served by the API: \
         `velarx-kube` makes them from the host",
    ))
}

/// `GET /generate/{name}/systemd`: the units of a container or a pod.
async fn systemd(call: Call) -> ApiResult {
    for flag in ["new", "templateUnitFile"] {
        if call.q_bool(flag, false)? {
            return Err(ApiError::bad_request(format!(
                "{flag} is not supported: it makes the container from its command line; \
                 velarx's units are Quadlet's (.container) or `velarx run` in a unit"
            )));
        }
    }
    let num = |name: &str| -> ApiResult<Option<u32>> {
        match call.q(name) {
            None | Some("") => Ok(None),
            Some(v) => v.parse().map(Some).map_err(|_| call.bad_parameter(name)),
        }
    };
    let spec = SystemdSpec {
        use_name: call.q_bool("useName", false)?,
        no_header: call.q_bool("noHeader", false)?,
        restart_policy: call.q("restartPolicy").map(str::to_string),
        restart_sec: num("restartSec")?,
        start_timeout: num("startTimeout")?,
        stop_timeout: num("stopTimeout")?,
        container_prefix: call.q("containerPrefix").map(str::to_string),
        pod_prefix: call.q("podPrefix").map(str::to_string),
        separator: call.q("separator").map(str::to_string),
        wants: all(&call, "wants"),
        after: all(&call, "after"),
        requires: all(&call, "requires"),
        env: all(&call, "additionalEnvVariables"),
    };
    let units: serde_json::Map<String, serde_json::Value> =
        engine_call!(call.engine, systemd_generate(call.param(0), spec))?
            .units
            .into_iter()
            .map(|(name, unit)| (name, json!(unit)))
            .collect();
    Ok(reply::json(200, &units))
}

pub(super) static ROUTES: &[Route] = &[
    route!("POST", "/kube/apply", LIBPOD, None, kube),
    route!("GET", "/generate/kube", LIBPOD, None, kube),
    route!("GET", "/kube/generate", LIBPOD, None, kube),
    route!("GET", "/generate/{}/systemd", LIBPOD, None, systemd),
    route!("POST", "/play/kube", LIBPOD, None, kube),
    route!("POST", "/kube/play", LIBPOD, None, kube),
    route!("DELETE", "/play/kube", LIBPOD, None, kube),
    route!("DELETE", "/kube/play", LIBPOD, None, kube),
];
