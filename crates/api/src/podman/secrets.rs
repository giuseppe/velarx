// SPDX-License-Identifier: Apache-2.0
//! Secrets: libpod's and Docker's routes.  The data crosses in base64 (a
//! secret is at most 512 kB), as the body of libpod's create or the field of
//! Docker's.

use super::call::Call;
use super::error::{ApiError, ApiResult};
use super::reply;
use super::{route, Route};
use crate::engine::engine_call;
use crate::engine::NewSecret;
use base64::Engine as _;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

/// The most a secret has, as the engine's.
pub(crate) const SECRET_MAX_SIZE: usize = 512_000;

#[derive(Deserialize, Default)]
#[serde(default)]
struct DockerSecret {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Data")]
    data: String,
    #[serde(rename = "Labels")]
    labels: HashMap<String, String>,
    #[serde(rename = "Driver")]
    driver: Option<DockerDriver>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DockerDriver {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Options")]
    options: HashMap<String, String>,
}

/// libpod: the body is the data, name, driver and labels (JSON) are in the
/// query.  Docker: `{"Name", "Data" (base64), "Labels", "Driver"}`.
fn pairs(map: HashMap<String, String>) -> BTreeMap<String, String> {
    map.into_iter().collect()
}

fn too_large() -> ApiError {
    ApiError::new(
        413,
        format!("the secret is larger than {SECRET_MAX_SIZE} bytes"),
    )
}

async fn update(_call: Call) -> ApiResult {
    Err(ApiError::not_implemented("update is not supported"))
}

async fn create(mut call: Call) -> ApiResult {
    if !call.libpod {
        let body: DockerSecret = call.json_or_default().await?;
        if body.data.is_empty() {
            return Err(ApiError::bad_request("no secret data"));
        }
        // checked here as the API server does (a bad encoding first, then
        // the size), so that no more than a secret goes to the engine
        let data = base64::engine::general_purpose::STANDARD
            .decode(body.data.as_bytes())
            .map_err(|_| ApiError::bad_request("the secret data is not valid base64"))?;
        if data.len() > SECRET_MAX_SIZE {
            return Err(too_large());
        }
        let (driver, driver_opts) = match body.driver {
            Some(d) => (Some(d.name).filter(|n| !n.is_empty()), d.options),
            None => (None, HashMap::new()),
        };
        let id = call
            .engine
            .secret_create(NewSecret {
                name: &body.name,
                data: bytes::Bytes::from(data),
                driver: driver.as_deref(),
                driver_opts: pairs(driver_opts),
                labels: pairs(body.labels),
                replace: false,
                ignore: false,
            })
            .await?;
        return Ok(reply::json(200, &serde_json::json!({"ID": id})));
    }
    // (more than a secret is refused here, before the engine is called)
    let data = axum::body::to_bytes(call.take_body(), SECRET_MAX_SIZE)
        .await
        .map_err(|_| too_large())?;
    let json_map = |key: &str| -> ApiResult<HashMap<String, String>> {
        match call.q(key) {
            Some(l) if !l.is_empty() => serde_json::from_str(l)
                .map_err(|_| ApiError::bad_request(format!("invalid {key} `{l}`"))),
            _ => Ok(HashMap::new()),
        }
    };
    let driver = call.q("driver").filter(|d| !d.is_empty());
    let driver_opts = json_map("driveropts")?;
    let labels = json_map("labels")?;
    let replace = call.q_bool("replace", false)?;
    let ignore = call.q_bool("ignore", false)?;
    let name = call.q("name").unwrap_or("");
    let id = call
        .engine
        .secret_create(NewSecret {
            name,
            data,
            driver,
            driver_opts: pairs(driver_opts),
            labels: pairs(labels),
            replace,
            ignore,
        })
        .await?;
    Ok(reply::json(200, &serde_json::json!({"ID": id})))
}

async fn list(call: Call) -> ApiResult {
    let filters = call.filters()?;
    let secrets = call.engine.secret_list(&filters).await?;
    let out: Vec<serde_json::Value> = secrets
        .iter()
        .map(|s| velarx_shape::secret::document(s, call.libpod))
        .collect();
    Ok(reply::json(200, &out))
}

async fn inspect(call: Call) -> ApiResult {
    let show = call.q_bool("showsecret", false)?;
    let secret = call.engine.secret_inspect(call.param(0), show).await?;
    Ok(reply::json(
        200,
        &velarx_shape::secret::document(&secret, call.libpod),
    ))
}

async fn exists(call: Call) -> ApiResult {
    engine_call!(call.engine, secret_exists(call.param(0)))?;
    Ok(reply::empty(204))
}

async fn remove(call: Call) -> ApiResult {
    engine_call!(call.engine, secret_remove(call.param(0), false))?;
    Ok(reply::empty(204))
}

/// libpod: `DELETE /secrets/{name}?all=true` removes them all.
async fn remove_all(call: Call) -> ApiResult {
    let all = call.q_bool("all", false)?;
    engine_call!(call.engine, secret_remove(call.param(0), all))?;
    Ok(reply::empty(204))
}

pub(super) static ROUTES: &[Route] = &[
    route!("POST", "/secrets/create", BOTH, Secret, create),
    route!("POST", "/secrets/{}/update", COMPAT, Secret, update),
    route!("GET", "/secrets/json", LIBPOD, Secret, list),
    route!("GET", "/secrets", COMPAT, Secret, list),
    route!("GET", "/secrets/{}/json", LIBPOD, Secret, inspect),
    route!("GET", "/secrets/{}/exists", LIBPOD, Secret, exists),
    route!("GET", "/secrets/{}", COMPAT, Secret, inspect),
    route!("DELETE", "/secrets/{}", LIBPOD, Secret, remove_all),
    route!("DELETE", "/secrets/{}", COMPAT, Secret, remove),
];
