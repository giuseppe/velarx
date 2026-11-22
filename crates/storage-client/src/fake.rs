// SPDX-License-Identifier: Apache-2.0
//! A storage driver in the process of the tests: a listener on a socket of a
//! temporary directory, a thread for each connection, and a handler the test
//! sets.  It answers `GetInfo` itself (the test can change what it says) and
//! hands every other call to the handler with the connection, so that a test
//! writes the replies (and the descriptors, and the pauses) it wants to see
//! the client's reactions to.  There is no real server in this package: the
//! reference one is another package.

use serde_json::{json, Value};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use velarx_wire::varlink::{call_parameters, encode_error, encode_reply, parse_call, Conn};

/// A call the fake got.
pub struct Call {
    /// The method without the interface (`HasLayers`).
    pub method: String,
    pub params: Value,
    pub more: bool,
    pub fds: Vec<OwnedFd>,
}

pub type Handler = dyn Fn(Call, &mut Conn) + Send + Sync;

pub struct Fake {
    pub socket: PathBuf,
    _dir: tempfile::TempDir,
    /// What `GetInfo` says.
    pub info: Arc<Mutex<Value>>,
    /// The calls, in the order they came (`GetInfo` included).
    pub calls: Arc<Mutex<Vec<(String, Value)>>>,
    handler: Arc<Mutex<Arc<Handler>>>,
    /// The listening socket, to end the accept of the thread that serves.
    listener: UnixListener,
}

/// What `GetInfo` says by default: a rootless driver of images mounted as
/// copies.
pub fn default_info() -> Value {
    json!({
        "proto": 2,
        "version": "1.2.3",
        "name": "fake",
        "capabilities": ["rootless", "size_limit", "verity_pull_only", "a_capability_of_a_later_version"],
        "limits": {
            "max_message": 1048576, "max_fds": 16, "max_wants": 4096, "max_ranges": 4096,
            "max_layers": 128, "a_limit_of_a_later_version": 7
        },
        "mounts": {
            "root": {"idmap": ["driver_mount", "at_copy"]},
            "volume": {"idmap": ["at_copy"]}
        }
    })
}

/// Send a reply.
pub fn reply(conn: &mut Conn, parameters: &Value, continues: bool, fds: &[BorrowedFd<'_>]) {
    let _ = conn.send(&encode_reply(parameters, continues), fds);
}

/// Send an error of the interface.
pub fn error(conn: &mut Conn, name: &str, parameters: &Value) {
    let _ = conn.send(&encode_error(name, parameters), &[]);
}

impl Fake {
    pub fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("storage.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let fake = Self {
            socket,
            _dir: dir,
            info: Arc::new(Mutex::new(default_info())),
            calls: Arc::default(),
            handler: Arc::new(Mutex::new(Arc::new(|c: Call, conn: &mut Conn| {
                error(
                    conn,
                    "org.velarx.Storage.Unsupported",
                    &json!({"reason": format!("the fake has no handler for {}", c.method)}),
                );
            }))),
            listener: listener.try_clone().unwrap(),
        };
        let (info, calls, handler) = (fake.info.clone(), fake.calls.clone(), fake.handler.clone());
        // (the accept ends with an error when the fake is dropped)
        std::thread::spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                let (info, calls, handler) = (info.clone(), calls.clone(), handler.clone());
                std::thread::spawn(move || serve(Conn::from_stream(stream), info, calls, handler));
            }
        });
        fake
    }

    /// What the fake does with a call that is not `GetInfo`.
    pub fn handle(&self, f: impl Fn(Call, &mut Conn) + Send + Sync + 'static) {
        *self.handler.lock().unwrap() = Arc::new(f);
    }

    /// The calls of `method` the fake got, with their parameters.
    pub fn calls_of(&self, method: &str) -> Vec<Value> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| m == method)
            .map(|(_, p)| p.clone())
            .collect()
    }

    /// Say something else in `GetInfo` from now on.
    pub fn say(&self, f: impl FnOnce(&mut Value)) {
        f(&mut self.info.lock().unwrap());
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        rustix::net::shutdown(&self.listener, rustix::net::Shutdown::Both)
            .expect("end the accept of the fake");
    }
}

fn serve(
    mut conn: Conn,
    info: Arc<Mutex<Value>>,
    calls: Arc<Mutex<Vec<(String, Value)>>>,
    handler: Arc<Mutex<Arc<Handler>>>,
) {
    loop {
        let Ok(bytes) = conn.message() else { return };
        let fds = conn.take_fds();
        let Ok(head) = parse_call(&bytes) else { return };
        let params: Value = call_parameters::<Value>(&bytes).unwrap_or(Value::Null);
        let method = head
            .method
            .strip_prefix("org.velarx.Storage.")
            .unwrap_or(&head.method)
            .to_string();
        calls.lock().unwrap().push((method.clone(), params.clone()));
        if method == "GetInfo" {
            let say = info.lock().unwrap().clone();
            reply(&mut conn, &say, false, &[]);
            continue;
        }
        let call = Call {
            method,
            params,
            more: head.more,
            fds,
        };
        let h = handler.lock().unwrap().clone();
        h(call, &mut conn);
    }
}
