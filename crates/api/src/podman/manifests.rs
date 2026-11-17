// SPDX-License-Identifier: Apache-2.0
//! `/libpod/manifests`: manifest lists (`podman manifest`), in the forms of
//! the 3.x API (`create`, `add`, `push`, `DELETE ?digest=`) and of 4.x
//! (`POST /manifests/{name}`, `PUT` to modify, `/registry/{dest}`).  podman's
//! modification is decoded here, and made of typed calls of the engine.

use super::call::Call;
use super::error::{ApiError, ApiResult};
use super::reply;
use super::{route, Route};
use crate::engine::engine_call;
use crate::engine::Engine;
use futures::StreamExt;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use velarx_proto::engine::{InstanceSpec, ManifestArtifactSpec, MAX_ARTIFACT_FILES};
use velarx_proto::godecode;
use velarx_registry::auth::RegistryAccess;

/// The body of a modification, and of a 3.x `add`.
#[derive(Default)]
struct Modify {
    operation: String,
    images: Vec<String>,
    all: bool,
    annotation: Vec<String>,
    annotations: BTreeMap<String, String>,
    arch: String,
    os: String,
    os_version: String,
    variant: String,
    features: Vec<String>,
    os_features: Vec<String>,
    index_annotation: Vec<String>,
    index_annotations: BTreeMap<String, String>,
    subject: String,
    username: String,
    password: String,
    skiptlsverify: Option<bool>,
    // An artifact made of the files of a multipart body.
    artifact_type: Option<String>,
    artifact_layer_type: String,
    artifact_config_type: String,
    artifact_config: String,
    artifact_exclude_titles: bool,
    artifact_annotations: BTreeMap<String, String>,
    artifact_subject: String,
    // Paths on the engine's host: the files of an artifact are the parts
    // of a multipart body here.
    artifact_files: Vec<String>,
}

/// The members of a body, found by Go's rule (a name matches without regard
/// to case); one that is `null` is not there.
struct Members<'a>(&'a serde_json::Map<String, Value>);

impl Members<'_> {
    #[inline(never)]
    fn get(&self, names: &[&str]) -> Option<&Value> {
        let exact = names.iter().find_map(|n| self.0.get(*n));
        exact
            .or_else(|| {
                self.0
                    .iter()
                    .find(|(k, _)| names.iter().any(|n| n.eq_ignore_ascii_case(k)))
                    .map(|(_, v)| v)
            })
            .filter(|v| !v.is_null())
    }

    fn wrong(names: &[&str], what: &str) -> ApiError {
        ApiError::bad_request(format!(
            "invalid body: the member {} is not {what}",
            names[0]
        ))
    }

    #[inline(never)]
    fn text(&self, names: &[&str]) -> ApiResult<String> {
        match self.get(names) {
            None => Ok(String::new()),
            Some(Value::String(s)) => Ok(s.clone()),
            Some(_) => Err(Self::wrong(names, "a string")),
        }
    }

    #[inline(never)]
    fn opt_text(&self, names: &[&str]) -> ApiResult<Option<String>> {
        match self.get(names) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(Self::wrong(names, "a string")),
        }
    }

    #[inline(never)]
    fn flag(&self, names: &[&str]) -> ApiResult<Option<bool>> {
        match self.get(names) {
            None => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(Self::wrong(names, "a boolean")),
        }
    }

    #[inline(never)]
    fn texts(&self, names: &[&str]) -> ApiResult<Vec<String>> {
        match self.get(names) {
            None => Ok(Vec::new()),
            Some(Value::Array(a)) => a
                .iter()
                .map(|v| match v {
                    Value::String(s) => Ok(s.clone()),
                    _ => Err(Self::wrong(names, "a list of strings")),
                })
                .collect(),
            Some(_) => Err(Self::wrong(names, "a list")),
        }
    }

    #[inline(never)]
    fn map(&self, names: &[&str]) -> ApiResult<BTreeMap<String, String>> {
        match self.get(names) {
            None => Ok(BTreeMap::new()),
            Some(Value::Object(o)) => o
                .iter()
                .map(|(k, v)| match v {
                    Value::String(s) => Ok((k.clone(), s.clone())),
                    _ => Err(Self::wrong(names, "a map of strings")),
                })
                .collect(),
            Some(_) => Err(Self::wrong(names, "an object")),
        }
    }
}

/// `k=v` annotations.
fn parse_annotations(list: &[String]) -> ApiResult<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for a in list {
        let (k, v) = a
            .split_once('=')
            .ok_or_else(|| ApiError::bad_request(format!("no value given for annotation {a:?}")))?;
        out.insert(k.to_string(), v.to_string());
    }
    Ok(out)
}

impl Modify {
    /// The body of a modification, which podman decodes as a whole: an
    /// error is a 500 whose message says `what` was decoded.
    fn of_modification(bytes: &[u8], what: &str) -> ApiResult<Self> {
        Self::of(bytes).map_err(|e| {
            let m = e
                .message
                .strip_prefix("invalid body: ")
                .unwrap_or(&e.message);
            ApiError::internal(format!("{what}: {m}"))
        })
    }

    fn of(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self::default());
        }
        let body = godecode::first_value(bytes)
            .map_err(|e| ApiError::bad_request(format!("invalid body: {e}")))?;
        let Value::Object(o) = &body else {
            return Err(ApiError::bad_request("invalid body: not an object"));
        };
        let m = Members(o);
        Ok(Self {
            operation: m.text(&["operation"])?,
            images: m.texts(&["images"])?,
            all: m.flag(&["all"])?.unwrap_or(false),
            annotation: m.texts(&["annotation"])?,
            annotations: m.map(&["annotations"])?,
            arch: m.text(&["arch"])?,
            os: m.text(&["os"])?,
            os_version: m.text(&["os_version", "osversion"])?,
            variant: m.text(&["variant"])?,
            features: m.texts(&["features"])?,
            os_features: m.texts(&["os_features", "osfeatures"])?,
            index_annotation: m.texts(&["index_annotation", "indexannotation"])?,
            index_annotations: m.map(&["index_annotations", "indexannotations"])?,
            subject: m.text(&["subject", "indexsubject"])?,
            username: m.text(&["username"])?,
            password: m.text(&["password"])?,
            skiptlsverify: m.flag(&["skiptlsverify"])?,
            artifact_type: m.opt_text(&["artifact_type"])?,
            artifact_layer_type: m.text(&["artifact_layer_type"])?,
            artifact_config_type: m.text(&["artifact_config_type"])?,
            artifact_config: m.text(&["artifact_config"])?,
            artifact_exclude_titles: m.flag(&["artifact_exclude_titles"])?.unwrap_or(false),
            artifact_annotations: m.map(&["artifact_annotations"])?,
            artifact_subject: m.text(&["artifact_subject"])?,
            artifact_files: m.texts(&["artifact_files"])?,
        })
    }

    fn annotations(&self) -> ApiResult<BTreeMap<String, String>> {
        if !self.annotation.is_empty() && !self.annotations.is_empty() {
            return Err(ApiError::bad_request(
                "can not set both Annotation and Annotations",
            ));
        }
        if self.annotation.is_empty() {
            return Ok(self.annotations.clone());
        }
        parse_annotations(&self.annotation)
    }

    fn index_annotations(&self) -> ApiResult<BTreeMap<String, String>> {
        if !self.index_annotation.is_empty() && !self.index_annotations.is_empty() {
            return Err(ApiError::bad_request(
                "can not set both IndexAnnotation and IndexAnnotations",
            ));
        }
        if self.index_annotation.is_empty() {
            return Ok(self.index_annotations.clone());
        }
        parse_annotations(&self.index_annotation)
    }

    fn instance(&self) -> ApiResult<InstanceSpec> {
        Ok(InstanceSpec {
            annotations: self.annotations()?,
            architecture: self.arch.clone(),
            os: self.os.clone(),
            os_version: self.os_version.clone(),
            variant: self.variant.clone(),
            features: self.features.clone(),
            os_features: self.os_features.clone(),
        })
    }

    /// `tlsVerify` of the query, or the `SkipTLSVerify` of the body.
    fn tls_verify(&self, query: Option<bool>) -> bool {
        query.unwrap_or(!self.skiptlsverify.unwrap_or(false))
    }

    /// The access of the header, or the credentials of the body (the 4.x
    /// bindings put them there).
    fn access(&self, mut a: RegistryAccess) -> ApiResult<RegistryAccess> {
        if a.creds.is_none() && !self.username.is_empty() {
            a.creds = Some(
                velarx_registry::Credentials::parse_creds(&format!(
                    "{}:{}",
                    self.username, self.password
                ))
                .map_err(ApiError::bad_request)?,
            );
        }
        Ok(a)
    }
}

/// The images of a request, those of the store named by the ids of the API
/// (podman's image ids are the digests of the configurations).
async fn local_ids(engine: &Engine, images: &[String]) -> ApiResult<Vec<String>> {
    let mut out = Vec::with_capacity(images.len());
    for i in images {
        match i.strip_prefix("containers-storage:") {
            Some(r) => out.push(format!(
                "containers-storage:{}",
                engine_call!(engine, image_inspect(r))?.image.id
            )),
            None => out.push(i.clone()),
        }
    }
    Ok(out)
}

/// `tlsVerify` of the query, if given.
fn tls_query(call: &Call) -> ApiResult<Option<bool>> {
    match call.q("tlsVerify") {
        Some(_) => call.q_bool("tlsVerify", true).map(Some),
        None => Ok(None),
    }
}

/// `POST /manifests/create?name=` (3.x) and `POST /manifests/{name}` (4.x).
async fn create(mut call: Call) -> ApiResult {
    let v4 = call.at_least(4, 0);
    let name = if call.params.is_empty() {
        call.q("name").unwrap_or("").to_string()
    } else {
        call.param(0).to_string()
    };
    if name.is_empty() {
        return Err(ApiError::bad_request("a manifest list needs a name"));
    }
    let images: Vec<String> = call
        .q_all("images")
        .into_iter()
        .chain(call.q_all("image"))
        .flat_map(|s| s.split(','))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let amend = call.q_bool("amend", false)?;
    let all = call.q_bool("all", false)?;
    let tls_verify = call.q_bool("tlsVerify", true)?;
    let access = call.registry_access()?;
    // (`annotations`, a JSON object, then the `annotation` KEY=VALUE words)
    let mut annotations = match call.q("annotations").filter(|a| !a.is_empty()) {
        Some(a) => serde_json::from_str::<std::collections::BTreeMap<String, String>>(a)
            .map_err(|_| ApiError::bad_request(format!("invalid annotations `{a}`")))?,
        None => Default::default(),
    };
    annotations.extend(super::call::annotations(call.q_all("annotation"))?);
    // (the modification of the body: more images and options, all of them
    // the list's)
    let body = call.body_bytes(super::call::MAX_JSON_BODY).await?;
    let body = Modify::of(&body)?;
    let mut images = images;
    images.extend(body.images.iter().cloned());
    let images = local_ids(&call.engine, &images).await?;
    annotations.extend(body.index_annotations()?);
    let subject = Some(body.subject.clone()).filter(|s| !s.is_empty());
    let id = call
        .engine
        .manifest_create(
            &name,
            images,
            amend,
            all || body.all,
            tls_verify,
            annotations,
            body.instance()?,
            subject,
            &access,
        )
        .await?;
    Ok(reply::json(
        if v4 { 201 } else { 200 },
        &json!({ "Id": id }),
    ))
}

/// `GET /manifests/{name}/json`
async fn inspect(call: Call) -> ApiResult {
    let tls_verify = call.q_bool("tlsVerify", true)?;
    let list = call
        .engine
        .manifest_inspect(call.param(0), tls_verify, &call.registry_access()?)
        .await?;
    Ok(reply::json(
        200,
        &velarx_shape::manifest::index_document(&list),
    ))
}

/// A list that is not there is a 404 of the operations that need one.
async fn existing(engine: &Engine, name: &str) -> ApiResult<String> {
    match engine_call!(engine, manifest_exists(name)).map(|_| ()) {
        Ok(()) => {}
        // (podman's words: `{name}: image not known`)
        Err(e) if e.status == 404 => return Err(ApiError::not_found(name.to_string())),
        Err(e) => return Err(e),
    }
    Ok(engine
        .manifest_inspect(name, true, &RegistryAccess::default())
        .await?
        .id)
}

/// `POST /manifests/{name}/add` (3.x).
async fn add_v3(mut call: Call) -> ApiResult {
    let name = call.param(0).to_string();
    let tls = tls_query(&call)?;
    let access = call.registry_access()?;
    let bytes = call.body_bytes(super::call::MAX_JSON_BODY).await?;
    let body = Modify::of(&bytes)?;
    // (podman annotates the list with them: the engine's add has no such
    // thing)
    for (name, set) in [
        ("index_annotation", !body.index_annotation.is_empty()),
        ("index_annotations", !body.index_annotations.is_empty()),
        ("subject", !body.subject.is_empty()),
    ] {
        super::call::refuse_field(name, &Value::Bool(set))?;
    }
    existing(&call.engine, &name).await?;
    let images = local_ids(&call.engine, &body.images).await?;
    let id = call
        .engine
        .manifest_add_images(
            &name,
            images,
            body.all,
            body.instance()?,
            body.tls_verify(tls),
            &body.access(access)?,
        )
        .await?;
    Ok(reply::json(200, &json!({ "Id": id })))
}

/// The most bytes of the request part of a multipart modification.
const MAX_REQUEST: u64 = 1 << 20;
/// The most bytes of a multipart body (its files are memory files until
/// the engine took them).
const MAX_MULTIPART: u64 = 4 << 30;

/// The request and the files of a multipart modification: the files as
/// the titles podman gives them and their sealed memory files.  The body is
/// cut into its parts as it arrives.
async fn multipart_of(
    body: axum::body::Body,
    boundary: &str,
) -> ApiResult<(Modify, Vec<String>, Vec<OwnedFd>)> {
    use std::io::Read;
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let b = boundary.to_string();
    // (the request, then at most MAX_ARTIFACT_FILES files)
    let splitter = tokio::task::spawn_blocking(move || {
        let input = super::multipart::Chunks::new(rx);
        super::multipart::split(input, &b, MAX_ARTIFACT_FILES + 1)
    });
    let mut total = 0u64;
    let mut stream = body.into_data_stream();
    let mut read = Ok(());
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => {
                read = Err(ApiError::bad_request(format!("read the request body: {e}")));
                break;
            }
        };
        total += chunk.len() as u64;
        if total > MAX_MULTIPART {
            read = Err(ApiError::bad_request(
                "read the request body: length limit exceeded",
            ));
            break;
        }
        // (a splitter that stopped has its error)
        if tx.send(chunk).await.is_err() {
            break;
        }
    }
    drop(tx);
    let parts = splitter
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    read?;
    let parts = parts.map_err(|e| {
        if e.get_ref()
            .is_some_and(|e| e.is::<super::multipart::TooManyParts>())
        {
            ApiError::bad_request(format!("at most {MAX_ARTIFACT_FILES} files in an artifact"))
        } else {
            ApiError::bad_request(format!("invalid multipart body: {e}"))
        }
    })?;
    let mut parts = parts.into_iter();
    let first = parts
        .next()
        .ok_or_else(|| ApiError::bad_request("an empty multipart body"))?;
    let mut request = Vec::new();
    first
        .content
        .take(MAX_REQUEST + 1)
        .read_to_end(&mut request)?;
    if request.len() as u64 > MAX_REQUEST {
        return Err(ApiError::bad_request("the request part is too large"));
    }
    let modify = Modify::of_modification(&request, "decoding modify request in multipart request")?;
    let (mut titles, mut files) = (Vec::new(), Vec::new());
    for (i, p) in parts.enumerate() {
        // As podman names them: the file name, else the form name, its
        // last component.
        let given = p
            .filename
            .as_deref()
            .filter(|f| !f.is_empty())
            .unwrap_or(&p.name);
        let base = given.trim_end_matches('/').rsplit('/').next().unwrap_or("");
        let title = if base.is_empty() || base == "." || base == ".." {
            format!("upload{i}")
        } else {
            base.to_string()
        };
        if titles.contains(&title) {
            return Err(ApiError::bad_request(format!(
                "the file {title} is given twice"
            )));
        }
        titles.push(title);
        files.push(OwnedFd::from(p.content));
    }
    Ok((modify, titles, files))
}

/// What a modification did: podman's report and its status.
struct Changes {
    id: String,
    images: Vec<String>,
    files: Vec<String>,
    errors: Vec<String>,
}

impl Changes {
    fn status(&self) -> u16 {
        match (
            self.errors.is_empty(),
            self.images.is_empty() && self.files.is_empty(),
        ) {
            (true, _) => 200,
            (false, false) => 409,
            (false, true) => 400,
        }
    }

    /// podman's report: what is empty is left out.
    fn document(&self) -> Value {
        let mut o = serde_json::Map::new();
        o.insert("Id".into(), json!(self.id));
        for (key, v) in [
            ("images", &self.images),
            ("files", &self.files),
            ("errors", &self.errors),
        ] {
            if !v.is_empty() {
                o.insert(key.into(), json!(v));
            }
        }
        Value::Object(o)
    }
}

/// podman's refusal of an annotation (its `ManifestAnnotate`): what is of an
/// instance needs one, what is of the index needs none.
fn annotate_refusal(
    instance: Option<&str>,
    spec: &InstanceSpec,
    index_annotations: &BTreeMap<String, String>,
    subject: Option<&str>,
) -> Option<String> {
    if instance.is_none() {
        let what = [
            (!spec.annotations.is_empty(), "annotation"),
            (!spec.architecture.is_empty(), "architecture"),
            (!spec.features.is_empty(), "features"),
            (!spec.os.is_empty(), "OS"),
            (!spec.os_features.is_empty(), "OS features"),
            (!spec.os_version.is_empty(), "OS version"),
            (!spec.variant.is_empty(), "variant"),
        ];
        return what.iter().find(|(set, _)| *set).map(|(_, what)| {
            format!("setting {what} on an item in a manifest list requires an instance digest")
        });
    }
    if !index_annotations.is_empty() {
        return Some(
            "setting index-wide annotation in a manifest list requires no instance digest".into(),
        );
    }
    subject.map(|_| "setting subject for a manifest list requires no instance digest".into())
}

/// A digest as Go's `digest.Parse` takes it (an algorithm it knows, its
/// hexadecimal length).
fn is_digest(d: &str) -> bool {
    let Some((algorithm, hex)) = d.split_once(':') else {
        return false;
    };
    let length = match algorithm {
        "sha256" => 64,
        "sha384" => 96,
        "sha512" => 128,
        _ => return false,
    };
    hex.len() == length && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Update (add), remove or annotate the list `name` as `body` asks, the
/// files of an artifact (`titles` and their descriptors) added with an
/// update.
async fn apply(
    engine: &Engine,
    name: &str,
    target: &str,
    body: Modify,
    files: Option<(Vec<String>, Vec<OwnedFd>)>,
    tls: Option<bool>,
    access: RegistryAccess,
) -> ApiResult<Changes> {
    let list_id = existing(engine, name).await?;
    let access = body.access(access)?;
    let instance = body.instance()?;
    let index_annotations = body.index_annotations()?;
    let tls_verify = body.tls_verify(tls);
    let mut done = Changes {
        id: list_id.clone(),
        images: Vec::new(),
        files: Vec::new(),
        errors: Vec::new(),
    };
    match body.operation.to_ascii_lowercase().as_str() {
        "update" => {
            if !body.images.is_empty() {
                let local = local_ids(engine, &body.images).await?;
                match engine
                    .manifest_add_images(
                        &list_id,
                        local,
                        body.all,
                        instance.clone(),
                        tls_verify,
                        &access,
                    )
                    .await
                {
                    Ok(new) => {
                        done.id = new;
                        done.images = body.images.clone();
                    }
                    Err(e) => done.errors.push(e.message),
                }
                // (as podman's add: then the annotations and the subject of
                // the list)
                let subject = Some(body.subject.clone()).filter(|s| !s.is_empty());
                if done.errors.is_empty() && (!index_annotations.is_empty() || subject.is_some()) {
                    if let Err(e) = engine
                        .manifest_annotate(
                            &list_id,
                            None,
                            InstanceSpec::default(),
                            index_annotations.clone(),
                            subject,
                        )
                        .await
                    {
                        done.images.clear();
                        done.errors.push(e.message);
                    }
                }
            }
            if let (Some((titles, fds)), true) = (files, done.errors.is_empty()) {
                let spec = ManifestArtifactSpec {
                    titles: titles.clone(),
                    artifact_type: body.artifact_type.clone(),
                    layer_type: body.artifact_layer_type.clone(),
                    config_type: body.artifact_config_type.clone(),
                    config: body.artifact_config.clone(),
                    exclude_titles: body.artifact_exclude_titles,
                    annotations: body.artifact_annotations.clone(),
                    subject: body.artifact_subject.clone(),
                    instance: instance.clone(),
                };
                let added = engine
                    .manifest_add_artifact(&list_id, spec, tls_verify, &access, fds)
                    .await;
                // (then the annotations and the subject of the list)
                let subject = Some(body.subject.clone()).filter(|s| !s.is_empty());
                let annotated = match added {
                    Ok(_) if !index_annotations.is_empty() || subject.is_some() => engine
                        .manifest_annotate(
                            &list_id,
                            None,
                            InstanceSpec::default(),
                            index_annotations.clone(),
                            subject,
                        )
                        .await
                        .map(|_| ()),
                    other => other.map(|_| ()),
                };
                match annotated {
                    Ok(()) => done.files = titles,
                    Err(e) => done.errors.push(e.message),
                }
            }
        }
        "remove" => {
            for image in &body.images {
                // (podman's words)
                if !is_digest(image) {
                    done.errors.push(format!(
                        "invalid image digest \"{image}\": invalid checksum digest format"
                    ));
                    continue;
                }
                match engine_call!(engine, manifest_remove_instance(&list_id, image)).map(|r| r.id) {
                    Ok(new) => {
                        done.id = new;
                        done.images.push(image.clone());
                    }
                    Err(e) if e.status == 404 => done.errors.push(format!(
                        "no instance matching digest \"{image}\" found in manifest list: file does not exist"
                    )),
                    Err(e) => done.errors.push(e.message),
                }
            }
        }
        "annotate" => {
            let local = local_ids(engine, &body.images).await?;
            // (each target as the request names it, and as the engine does)
            let targets: Vec<Option<(&String, String)>> = if local.is_empty() {
                vec![None]
            } else {
                body.images.iter().zip(local).map(Some).collect()
            };
            let subject = Some(body.subject.clone()).filter(|s| !s.is_empty());
            for t in targets {
                if let Some(refused) = annotate_refusal(
                    t.as_ref().map(|(_, l)| l.as_str()),
                    &instance,
                    &index_annotations,
                    subject.as_deref(),
                ) {
                    done.errors.push(refused);
                    continue;
                }
                match engine
                    .manifest_annotate(
                        &list_id,
                        t.as_ref().map(|(_, l)| l.clone()),
                        instance.clone(),
                        index_annotations.clone(),
                        subject.clone(),
                    )
                    .await
                {
                    Ok(new) => {
                        done.id = new;
                        if let Some((given, _)) = t {
                            done.images.push(given.clone());
                        }
                    }
                    Err(e) if e.status == 404 && t.as_ref().is_some_and(|(g, _)| is_digest(g)) => {
                        done.errors.push(format!(
                            "no OCI manifest matching digest \"{}\" was found in list: no image instance matching the specified digest was found in the list or index",
                            t.as_ref().map_or("", |(g, _)| g.as_str())
                        ))
                    }
                    Err(e) => done.errors.push(e.message),
                }
            }
        }
        _ => {
            return Err(ApiError::bad_request(format!(
                "illegal operation \"{}\" for \"{target}\"",
                body.operation
            )))
        }
    }
    Ok(done)
}

/// `PUT /manifests/{name}` (4.x): update (add), remove or annotate; a
/// multipart body has the request in its first part and the files of an
/// artifact in the others.
async fn modify(mut call: Call) -> ApiResult {
    let name = call.param(0).to_string();
    let tls = tls_query(&call)?;
    let access = call.registry_access()?;
    let boundary = call.header("content-type").and_then(boundary);
    let (body, files) = match boundary {
        Some(b) => {
            let (body, titles, fds) = multipart_of(call.take_body(), &b).await?;
            (body, Some((titles, fds)))
        }
        None => {
            let bytes = call.body_bytes(super::call::MAX_JSON_BODY).await?;
            let body = Modify::of_modification(&bytes, "decoding modify request")?;
            if !body.artifact_files.is_empty() {
                return Err(ApiError::not_implemented(
                    "`artifact_files` is not supported: the files are the parts of a multipart body",
                ));
            }
            (body, None)
        }
    };
    let done = apply(&call.engine, &name, &call.target, body, files, tls, access).await?;
    Ok(reply::json(done.status(), &done.document()))
}

/// The boundary of a multipart content type.
fn boundary(content_type: &str) -> Option<String> {
    let mut parts = content_type.split(';');
    if !parts
        .next()?
        .trim()
        .to_ascii_lowercase()
        .starts_with("multipart/")
    {
        return None;
    }
    for p in parts {
        let (k, v) = p.split_once('=')?;
        if k.trim().eq_ignore_ascii_case("boundary") {
            let v = v.trim().trim_matches('"');
            if !v.is_empty() && v.len() <= 70 {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// The push of the list `name` to `destination`, as the query says.
async fn push_list(call: &Call, name: &str, destination: &str) -> ApiResult<String> {
    call.refuse_params(&["forceCompressionFormat"])?;
    call.refuse_set(&["compressionLevel", "addCompression", "format"])?;
    let all = call.q_bool("all", false)?;
    let tls_verify = call.q_bool("tlsVerify", true)?;
    let access = call.registry_access()?;
    let compression = match call.q("compressionFormat").filter(|c| !c.is_empty()) {
        Some(c) => Some(
            velarx_proto::engine::LayerCompression::of_word(c)
                .ok_or_else(|| ApiError::bad_request(format!("invalid compression `{c}`")))?,
        ),
        None => None,
    };
    call.engine
        .manifest_push(name, destination, all, tls_verify, compression, &access)
        .await
}

/// `POST /manifests/{name}/push?destination=` (3.x).
async fn push_v3(call: Call) -> ApiResult {
    let destination = call
        .q("destination")
        .filter(|d| !d.is_empty())
        .ok_or_else(|| ApiError::bad_request("missing the destination"))?
        .to_string();
    let digest = push_list(&call, call.param(0), &destination).await?;
    Ok(reply::json(200, &json!({ "Id": digest })))
}

/// `POST /manifests/{name}/registry/{destination}` (4.x): with `quiet=false`
/// the progress as lines.
async fn push(call: Call) -> ApiResult {
    let (name, destination) = (call.param(0).to_string(), call.param(1).to_string());
    if call.q_bool("quiet", true)? {
        let digest = push_list(&call, &name, &destination).await?;
        return Ok(reply::json(200, &json!({ "Id": digest })));
    }
    let first = format!(
        "{}\n",
        json!({"stream": format!("Pushing {name} to {destination}\n")})
    );
    let rest = async move {
        let last = match push_list(&call, &name, &destination).await {
            Ok(digest) => json!({ "Id": digest }),
            Err(e) => json!({ "error": e.message }),
        };
        Ok::<_, std::io::Error>(bytes::Bytes::from(format!("{last}\n")))
    };
    let lines = futures::stream::once(std::future::ready(Ok::<_, std::io::Error>(
        bytes::Bytes::from(first),
    )))
    .chain(futures::stream::once(rest));
    Ok(reply::with_type(
        200,
        "application/json",
        axum::body::Body::from_stream(lines),
    ))
}

async fn exists(call: Call) -> ApiResult {
    engine_call!(call.engine, manifest_exists(call.param(0)))?;
    Ok(reply::empty(204))
}

/// `DELETE /manifests/{name}`: the list (4.x), or `?digest=` an instance
/// of it (3.x).
async fn delete(call: Call) -> ApiResult {
    let v4 = call.at_least(4, 0);
    let ignore = v4 && call.q_bool("ignore", false)?;
    let digest = call.q("digest").filter(|d| !d.is_empty());
    let name = call.param(0);
    if !v4 {
        let digest = digest
            .filter(|d| is_digest(d))
            .ok_or_else(|| ApiError::bad_request("invalid checksum digest format"))?;
        let id = engine_call!(call.engine, manifest_remove_instance(name, digest))?.id;
        return Ok(reply::json(200, &json!({"Id": id})));
    }
    match engine_call!(call.engine, manifest_remove(name)) {
        Ok(r) => Ok(reply::json(
            200,
            &json!({"Deleted": [r.id], "Untagged": r.names, "Errors": [], "ExitCode": 0}),
        )),
        Err(e) if ignore && e.status == 404 => {
            Ok(reply::json(200, &json!({"Errors": [], "ExitCode": 0})))
        }
        Err(e) if e.status == 404 => Err(ApiError::not_found(name.to_string())),
        Err(e) => Err(e),
    }
}

pub(super) static ROUTES: &[Route] = &[
    route!("POST", "/manifests/create", LIBPOD, Image, create),
    route!("GET", "/manifests/{*}/json", LIBPOD, Image, inspect),
    route!("GET", "/manifests/{*}/exists", LIBPOD, Image, exists),
    route!("POST", "/manifests/{*}/add", LIBPOD, Image, add_v3),
    route!("POST", "/manifests/{*}/push", LIBPOD, Image, push_v3),
    route!("POST", "/manifests/{}/registry/{*}", LIBPOD, Image, push),
    route!("POST", "/manifests/{*}", LIBPOD, Image, create),
    route!("PUT", "/manifests/{*}", LIBPOD, Image, modify),
    route!("DELETE", "/manifests/{*}", LIBPOD, Image, delete),
];
