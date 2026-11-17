// SPDX-License-Identifier: Apache-2.0
//! Secrets: the engine's records of them (`SecretRecord`), with podman's
//! filters; `velarx_shape::secret` lays out podman's and Docker's
//! documents.

use super::call::Filters;
use super::error::{ApiError, ApiResult};
use super::events::Event;
use crate::api::AppState;
use std::sync::Arc;
use velarx_core::services::{CreateSecretOptions, SecretError, SecretInfo, SecretStore};
use velarx_proto::workload::EventKind;
use velarx_proto::workload::SecretRecord;
use velarx_wire::wire::SECRET_MAX_SIZE;

impl From<SecretError> for ApiError {
    fn from(e: SecretError) -> Self {
        match e {
            SecretError::NotFound(_) => ApiError::not_found(e.to_string()),
            SecretError::AlreadyExists(_) => ApiError::conflict(e.to_string()),
            SecretError::InUse { .. } => ApiError::invalid_state(e.to_string()),
            SecretError::Invalid(_) => ApiError::bad_request(e.to_string()),
            SecretError::TooLarge => ApiError::new(413, e.to_string()),
            e => ApiError::internal(e.to_string()),
        }
    }
}

/// The store of the daemon, opened on first use.
pub(super) async fn store(state: &AppState) -> ApiResult<Arc<SecretStore>> {
    state
        .podman
        .secrets
        .get_or_try_init(|| async {
            SecretStore::new(
                state.db.clone(),
                state.config.server.root_dir.join("secrets"),
            )
            .await
            .map(Arc::new)
        })
        .await
        .cloned()
        .map_err(Into::into)
}

/// A secret as the engine answers it, without its data.
fn record(s: &SecretInfo) -> SecretRecord {
    SecretRecord {
        id: s.id.clone(),
        name: s.name.clone(),
        driver: s.driver.clone(),
        driver_options: s.driver_opts.clone().into_iter().collect(),
        labels: s.labels.clone().into_iter().collect(),
        created_ns: s.created,
        updated_ns: s.updated,
        data: None,
    }
}

/// podman's secret filters, name and id; any other is a 500.
fn check_filters(filters: &Filters) -> ApiResult<()> {
    match filters
        .keys()
        .find(|k| !matches!(k.to_lowercase().as_str(), "name" | "id"))
    {
        Some(k) => Err(ApiError::bad_request(format!("invalid filter {k:?}"))),
        None => Ok(()),
    }
}

fn matches(filters: &Filters, s: &SecretInfo) -> bool {
    let names = filters.get("name");
    if !names.is_empty() && !names.iter().any(|n| s.name.contains(n.as_str())) {
        return false;
    }
    let ids = filters.get("id");
    ids.is_empty() || ids.iter().any(|i| s.id.starts_with(i.as_str()))
}

/// The secrets `filters` selects.
pub(crate) async fn list_of(state: &AppState, filters: &Filters) -> ApiResult<Vec<SecretRecord>> {
    check_filters(filters)?;
    let store = store(state).await?;
    Ok(store
        .list()
        .await?
        .iter()
        .filter(|s| matches(filters, s))
        .map(record)
        .collect())
}

/// A secret, with its data with `show_data`.
pub(crate) async fn inspect_of(
    state: &AppState,
    name: &str,
    show_data: bool,
) -> ApiResult<SecretRecord> {
    let store = store(state).await?;
    if show_data {
        let (info, data) = store.data(name).await?;
        Ok(SecretRecord {
            data: Some(data),
            ..record(&info)
        })
    } else {
        Ok(record(&store.lookup(name).await?))
    }
}

/// The secret `name` is there, or the error of the API.
pub(crate) async fn exists_of(state: &AppState, name: &str) -> ApiResult<()> {
    store(state).await?.lookup(name).await?;
    Ok(())
}

fn emit_remove(state: &AppState, s: &SecretInfo) {
    state
        .podman
        .events
        .emit(Event::new(EventKind::Secret, "remove", &s.id, &s.name));
}

pub(crate) async fn remove_of(state: &AppState, name: &str) -> ApiResult<()> {
    let removed = store(state).await?.remove(name).await?;
    emit_remove(state, &removed);
    Ok(())
}

pub(crate) async fn remove_all_of(state: &AppState) -> ApiResult<()> {
    let store = store(state).await?;
    for s in store.list().await? {
        let removed = store.remove(&s.id).await?;
        emit_remove(state, &removed);
    }
    Ok(())
}

/// Create a secret: its ID.
pub(crate) async fn create_of(
    state: &AppState,
    name: &str,
    opts: CreateSecretOptions,
    data: &[u8],
) -> ApiResult<String> {
    if data.len() > SECRET_MAX_SIZE {
        return Err(ApiError::new(
            413,
            format!("the secret is larger than {SECRET_MAX_SIZE} bytes"),
        ));
    }
    let store = store(state).await?;
    let id = store.create(name, opts, data).await?;
    state
        .podman
        .events
        .emit(Event::new(EventKind::Secret, "create", &id, name));
    Ok(id)
}
