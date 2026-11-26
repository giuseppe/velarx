// SPDX-License-Identifier: Apache-2.0
//! Exec sessions: create, inspect, start (the streams are the engine's
//! socket, spliced with the client's connection), resize, remove, kill.

use super::call::Call;
use super::error::{ApiError, ApiResult};
use super::hijack;
use super::reply;
use super::{route, Route};
use crate::engine::engine_call;
use serde::Serialize;
use serde_json::Value;
use velarx_proto::engine::Condition;
use velarx_proto::godecode;
use velarx_proto::workload::{ExecRecord, ExecSpec, RunState};

/// The most bytes of the body of an exec request.
const MAX_EXEC_BODY: usize = 1 << 20;

/// The body of the request: a JSON object, none when it is empty.
async fn body(call: &mut Call) -> ApiResult<Value> {
    let bytes = call.body_bytes(MAX_EXEC_BODY).await?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    Ok(godecode::first_value(&bytes)?)
}

/// The field of a body, by its name in any case (what podman's decoder does).
fn field<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    let o = v.as_object()?;
    o.get(k).or_else(|| {
        o.iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(k))
            .map(|(_, v)| v)
    })
}

/// The member `k` of a body when it is there and not null (as Go's
/// decoder, which leaves the zero value for a null).
fn member<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    field(v, k).filter(|x| !x.is_null())
}

/// The 400 for a member that is not of its type.
fn wrong_type(k: &str, want: &str, got: &Value) -> ApiError {
    let got = match got {
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        _ => "object",
    };
    ApiError::bad_request(format!(
        "json: cannot unmarshal {got} into Go struct field {k} of type {want}"
    ))
}

fn text<'a>(v: &'a Value, k: &str) -> ApiResult<&'a str> {
    match member(v, k) {
        None => Ok(""),
        Some(Value::String(s)) => Ok(s),
        Some(x) => Err(wrong_type(k, "string", x)),
    }
}

fn flag(v: &Value, k: &str) -> ApiResult<bool> {
    match member(v, k) {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(x) => Err(wrong_type(k, "bool", x)),
    }
}

fn strings(v: &Value, k: &str) -> ApiResult<Vec<String>> {
    match member(v, k) {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| match x {
                Value::String(s) => Ok(s.clone()),
                x => Err(wrong_type(k, "string", x)),
            })
            .collect(),
        Some(x) => Err(wrong_type(k, "[]string", x)),
    }
}

/// The session podman's body asks for; podman's 400 for a variable of the
/// environment without a value.
fn spec_of(body: &Value) -> ApiResult<ExecSpec> {
    let mut env = std::collections::BTreeMap::new();
    for e in strings(body, "Env")? {
        let Some((k, v)) = e.split_once('=') else {
            return Err(ApiError::bad_request(format!(
                "environment variable {e:?} badly formed, must be key=value"
            )));
        };
        env.insert(k.to_string(), v.to_string());
    }
    Ok(ExecSpec {
        command: strings(body, "Cmd")?,
        env,
        work_dir: text(body, "WorkingDir")?.to_string(),
        user: text(body, "User")?.to_string(),
        tty: flag(body, "Tty")?,
        stdin: flag(body, "AttachStdin")?,
        stdout: flag(body, "AttachStdout")?,
        stderr: flag(body, "AttachStderr")?,
        privileged: flag(body, "Privileged")?,
        detach_keys: text(body, "DetachKeys")?.to_string(),
        timeout_ms: None,
        errors_apart: false,
    })
}

/// Podman's inspect of a session, its members in podman's order.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Inspected<'a> {
    /// (once the command ended: not before it started)
    can_remove: bool,
    #[serde(rename = "ContainerID")]
    container_id: &'a str,
    detach_keys: &'a str,
    exit_code: i64,
    #[serde(rename = "ID")]
    id: &'a str,
    open_stderr: bool,
    open_stdin: bool,
    open_stdout: bool,
    running: bool,
    pid: i64,
    process_config: ProcessConfig<'a>,
}

#[derive(Serialize)]
struct ProcessConfig<'a> {
    /// (null without arguments, as podman's)
    arguments: Option<&'a [String]>,
    entrypoint: &'a str,
    privileged: bool,
    tty: bool,
    user: &'a str,
}

fn document_of(e: &ExecRecord) -> Inspected<'_> {
    Inspected {
        can_remove: e.exit_code.is_some(),
        container_id: &e.container_id,
        detach_keys: &e.detach_keys,
        exit_code: e.exit_code.unwrap_or(0),
        id: &e.id,
        open_stderr: e.stderr,
        open_stdin: e.stdin,
        open_stdout: e.stdout,
        running: e.running,
        pid: e.pid,
        process_config: ProcessConfig {
            arguments: e.command.get(1..).filter(|a| !a.is_empty()),
            entrypoint: e.command.first().map_or("", String::as_str),
            privileged: e.privileged,
            tty: e.tty,
            user: &e.user,
        },
    }
}

/// `POST /containers/{name}/exec`
async fn create(mut call: Call) -> ApiResult {
    let spec = spec_of(&body(&mut call).await?)?;
    let id = match engine_call!(call.engine, exec_create(call.param(0), spec)) {
        Ok(created) => created.id,
        Err(e) => return Err(create_refused(&call, e).await),
    };
    Ok(reply::json(201, &serde_json::json!({"Id": id})))
}

/// The answer to a create the engine refused for the state of the
/// container: a 409 that says so for a paused one, a 500 for another.
async fn create_refused(call: &Call, e: ApiError) -> ApiError {
    if !e.is(Condition::InvalidState) {
        return e;
    }
    match engine_call!(call.engine, container_inspect(call.param(0), false)) {
        Ok(found) if found.container.state == RunState::Paused => ApiError::conflict(format!(
            "cannot create exec session as container {} is paused",
            found.container.id
        )),
        _ => e.as_podman_failure(),
    }
}

/// `GET /exec/{id}/json`
async fn inspect(call: Call) -> ApiResult {
    let exec = engine_call!(call.engine, exec_inspect(call.param(0)))?.exec;
    Ok(reply::json(200, &document_of(&exec)))
}

/// `POST /exec/{id}/start`
async fn start(mut call: Call) -> ApiResult {
    let b = body(&mut call).await?;
    let upgraded = hijack::upgraded(&call);
    let id = call.param(0).to_string();
    let int = |k| field(&b, k).and_then(Value::as_i64).unwrap_or(0);
    let (detach, h, w) = (flag(&b, "Detach")?, int("h"), int("w"));
    // (in a task of its own: a client that hangs up before the answer, which
    // drops this request, still has its command started, and it goes on, as
    // podman's)
    let engine = call.engine.clone();
    let started = tokio::spawn(async move { engine.exec_start(&id, upgraded, detach, h, w).await })
        .await
        .map_err(|e| ApiError::internal(format!("exec start: {e}")))?;
    match started? {
        None => Ok(reply::empty(200)),
        Some(h) => hijack::respond(&mut call, h),
    }
}

/// `POST /exec/{id}/resize`
async fn resize(call: Call) -> ApiResult {
    let (h, w) = (call.q_i64("h", 0)?, call.q_i64("w", 0)?);
    let running = call.q_bool("running", false)?;
    engine_call!(call.engine, exec_resize(call.param(0), h, w, running))?;
    Ok(reply::with_type(201, "application/json", "{}\n"))
}

/// `POST /exec/{id}/remove`
async fn remove(mut call: Call) -> ApiResult {
    let b = body(&mut call).await?;
    let force = flag(&b, "Force")?;
    engine_call!(call.engine, exec_remove(call.param(0), force))?;
    Ok(reply::empty(200))
}

/// `POST /exec/{id}/kill`
async fn kill(call: Call) -> ApiResult {
    engine_call!(
        call.engine,
        exec_kill(call.param(0), call.q("signal").unwrap_or(""))
    )?;
    Ok(reply::json(200, &serde_json::json!("OK")))
}

pub(super) static ROUTES: &[Route] = &[
    route!("POST", "/exec/{}/kill", LIBPOD, Exec, kill),
    route!("POST", "/containers/{}/exec", BOTH, Container, create),
    route!("GET", "/exec/{}/json", BOTH, Exec, inspect),
    route!("POST", "/exec/{}/start", BOTH, Exec, start),
    route!("POST", "/exec/{}/resize", BOTH, Exec, resize),
    route!("POST", "/exec/{}/remove", LIBPOD, Exec, remove),
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_member_of_another_type_is_a_400_not_its_default() {
        for (member, body) in [
            ("User", json!({"User": 1000})),
            ("Cmd", json!({"Cmd": "ls"})),
            ("Cmd", json!({"Cmd": ["ls", 5]})),
            ("Env", json!({"Env": "A=1"})),
            ("Env", json!({"Env": [true]})),
            ("Tty", json!({"Tty": "yes"})),
            ("WorkingDir", json!({"WorkingDir": ["/"]})),
            ("AttachStdout", json!({"AttachStdout": 1})),
            ("Privileged", json!({"Privileged": "false"})),
            // (the name in any case, as the members are found)
            ("Tty", json!({"tty": "yes"})),
        ] {
            let e = spec_of(&body).unwrap_err();
            assert_eq!(e.status.as_u16(), 400, "{body}");
            assert!(e.message.contains(member), "{}", e.message);
        }
        assert!(flag(&json!({"Detach": "yes"}), "Detach").is_err());
    }

    #[test]
    fn an_absent_or_null_member_is_its_default() {
        let spec = spec_of(&json!({"Env": null, "User": null, "Tty": null})).unwrap();
        assert!(spec.env.is_empty() && spec.user.is_empty() && !spec.tty);
        assert!(spec_of(&Value::Null).unwrap().command.is_empty());
        let spec = spec_of(&json!({"Cmd": ["ls", "-l"], "User": "1000", "Tty": true})).unwrap();
        assert_eq!(
            (spec.command, spec.user, spec.tty),
            (vec!["ls".into(), "-l".into()], "1000".into(), true)
        );
    }
}
