// SPDX-License-Identifier: Apache-2.0
//! The calls of systemd's manager the engine and the monitor make,
//! `StartTransientUnit` for a scope (or a slice), `SetUnitProperties`,
//! `StopUnit`, and the `Delegate` property of a unit, over the manager's
//! private socket
//! (`$XDG_RUNTIME_DIR/systemd/private`, `/run/systemd/private` for root):
//! what `systemd-run --scope` does, without starting a program (several
//! milliseconds of every `run`) and without the bus daemon.
//!
//! The private socket speaks the D-Bus wire protocol with no `Hello`: one
//! SASL `EXTERNAL` authentication, then the method call.  Only what these
//! calls need is here: a marshaller for `ssa(sv)a(sa(sv))`, `sba(sv)` and
//! `ss`, and a reader of the reply (a method return, or an error name and
//! message).

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long the manager has to answer.
const TIMEOUT: Duration = Duration::from_secs(25);

/// The most a reply may be (the specification's limit is 128 MiB; this
/// one answers with a job path).
const MAX_REPLY: usize = 1 << 20;

/// A property of a transient unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Property {
    Str(&'static str, String),
    Bool(&'static str, bool),
    U64(&'static str, u64),
    Pids(Vec<u32>),
    /// An array of bytes (`ay`): a CPU or memory node mask
    Bytes(&'static str, Vec<u8>),
    /// An array of `(string, u64)` (`a(st)`): a limit for each device
    /// (`IOReadBandwidthMax`, `IODeviceWeight`...), the device as a path
    Devices(&'static str, Vec<(String, u64)>),
}

/// The private socket of the manager of the user (or the system's, for
/// root).
pub fn private_socket(system: bool) -> Option<PathBuf> {
    if system {
        return Some(PathBuf::from("/run/systemd/private"));
    }
    Some(Path::new(&std::env::var_os("XDG_RUNTIME_DIR")?).join("systemd/private"))
}

/// The private socket of the manager this process asks: [`private_socket`],
/// else, with no `XDG_RUNTIME_DIR` (a unit with `User=` has none), the
/// runtime directory of the user.
pub fn manager_socket(system: bool) -> Result<PathBuf, velarx_base::ids::IdsError> {
    if let Some(socket) = private_socket(system) {
        return Ok(socket);
    }
    let uid = velarx_base::ids::host_uid()?;
    Ok(PathBuf::from(format!("/run/user/{uid}/systemd/private")))
}

/// A message in the D-Bus wire format, little endian.
#[derive(Default)]
struct Writer(Vec<u8>);

impl Writer {
    fn align(&mut self, n: usize) {
        while !self.0.len().is_multiple_of(n) {
            self.0.push(0);
        }
    }

    fn u32(&mut self, v: u32) {
        self.align(4);
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn string(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
    }

    fn signature(&mut self, s: &str) {
        self.0.push(s.len() as u8);
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
    }

    /// `a(...)`: the elements are written by `f`; the length that precedes
    /// them is that of the elements alone (after their alignment).
    fn array(&mut self, element_align: usize, f: impl FnOnce(&mut Self)) {
        self.u32(0);
        let at = self.0.len() - 4;
        self.align(element_align);
        let start = self.0.len();
        f(self);
        let len = (self.0.len() - start) as u32;
        self.0[at..at + 4].copy_from_slice(&len.to_le_bytes());
    }

    /// `(sv)`: a property of a unit.
    fn property(&mut self, p: &Property) {
        self.align(8);
        match p {
            Property::Str(name, v) => {
                self.string(name);
                self.signature("s");
                self.string(v);
            }
            Property::Bool(name, v) => {
                self.string(name);
                self.signature("b");
                self.u32(u32::from(*v));
            }
            Property::U64(name, v) => {
                self.string(name);
                self.signature("t");
                self.align(8);
                self.0.extend_from_slice(&v.to_le_bytes());
            }
            Property::Bytes(name, bytes) => {
                self.string(name);
                self.signature("ay");
                self.array(1, |w| w.0.extend_from_slice(bytes));
            }
            Property::Devices(name, devices) => {
                self.string(name);
                self.signature("a(st)");
                self.array(8, |w| {
                    for (path, value) in devices {
                        w.align(8);
                        w.string(path);
                        w.align(8);
                        w.0.extend_from_slice(&value.to_le_bytes());
                    }
                });
            }
            Property::Pids(pids) => {
                self.string("PIDs");
                self.signature("au");
                self.array(4, |w| {
                    for p in pids {
                        w.u32(*p);
                    }
                });
            }
        }
    }
}

/// The method call `member` of the manager with the arguments `body`, of
/// the signature `signature`.
fn method_call(serial: u32, member: &str, signature: &str, body: &Writer) -> Vec<u8> {
    call_of(
        serial,
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        member,
        signature,
        body,
    )
}

/// The method call `member` of `interface` of the object `path`.
fn call_of(
    serial: u32,
    path: &str,
    interface: &str,
    member: &str,
    signature: &str,
    body: &Writer,
) -> Vec<u8> {
    call_to(
        serial,
        &Target {
            destination: "org.freedesktop.systemd1",
            flags: 0,
            path,
            interface,
        },
        member,
        signature,
        body,
    )
}

/// Where a method call goes: the service, the object and its interface, and
/// the flags of the header.
struct Target<'a> {
    destination: &'a str,
    flags: u8,
    path: &'a str,
    interface: &'a str,
}

/// The method call `member` of `target` with the arguments `body`.
fn call_to(serial: u32, target: &Target, member: &str, signature: &str, body: &Writer) -> Vec<u8> {
    let mut msg = Writer::default();
    // endianness, METHOD_CALL, flags (0: a reply is wanted), version
    msg.0.extend_from_slice(&[b'l', 1, target.flags, 1]);
    msg.u32(body.0.len() as u32);
    msg.u32(serial);
    msg.array(8, |w| {
        let mut field = |code: u8, sig: &str, v: &str| {
            w.align(8);
            w.0.push(code);
            w.signature(sig);
            w.string(v);
        };
        field(1, "o", target.path);
        field(2, "s", target.interface);
        field(3, "s", member);
        field(6, "s", target.destination);
        // (a call with no arguments has no signature field)
        if !signature.is_empty() {
            w.align(8);
            w.0.push(8);
            w.signature("g");
            w.signature(signature);
        }
    });
    msg.align(8);
    msg.0.extend_from_slice(&body.0);
    msg.0
}

/// The method call `StartTransientUnit(name, "fail", properties, [])`.
fn start_transient_unit(serial: u32, name: &str, properties: &[Property]) -> Vec<u8> {
    let mut body = Writer::default();
    body.string(name);
    body.string("fail");
    body.array(8, |w| {
        for p in properties {
            w.property(p);
        }
    });
    body.array(8, |_| {});
    method_call(serial, "StartTransientUnit", "ssa(sv)a(sa(sv))", &body)
}

/// The method call `SetUnitProperties(name, runtime, properties)`: the
/// properties of the unit change now and last until it ends.
fn set_unit_properties(serial: u32, name: &str, properties: &[Property]) -> Vec<u8> {
    let mut body = Writer::default();
    body.string(name);
    // (runtime: not written to the unit files, which a transient unit has none of)
    body.u32(1);
    body.array(8, |w| {
        for p in properties {
            w.property(p);
        }
    });
    method_call(serial, "SetUnitProperties", "sba(sv)", &body)
}

/// The method call `StopUnit(name, "replace")`.
fn stop_unit_call(serial: u32, name: &str) -> Vec<u8> {
    let mut body = Writer::default();
    body.string(name);
    body.string("replace");
    method_call(serial, "StopUnit", "ss", &body)
}

/// The object path of the unit `name`: systemd's `bus_label_escape` of
/// the name, what is not an ASCII letter or digit (a digit first too) as
/// `_XX`.
fn unit_path(name: &str) -> String {
    let mut path = String::from("/org/freedesktop/systemd1/unit/");
    for (i, b) in name.bytes().enumerate() {
        if b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()) {
            path.push(b as char);
        } else {
            path.push_str(&format!("_{b:02x}"));
        }
    }
    path
}

/// The method call `Get(interface, property)` of the properties of the
/// unit `unit`.
fn get_property_call(serial: u32, unit: &str, interface: &str, property: &str) -> Vec<u8> {
    let mut body = Writer::default();
    body.string(interface);
    body.string(property);
    call_of(
        serial,
        &unit_path(unit),
        "org.freedesktop.DBus.Properties",
        "Get",
        "ss",
        &body,
    )
}

/// What the manager answered.
#[derive(Debug, PartialEq, Eq)]
enum Reply {
    /// The method returned: the first string of its answer (the path of
    /// the job a manager queued).
    Return(String),
    Error(String, String),
}

/// A `u32` at `at`, in the byte order of the message (`big`).
fn read_u32(b: &[u8], at: usize, big: bool) -> io::Result<u32> {
    let s: [u8; 4] = b
        .get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    Ok(if big {
        u32::from_be_bytes(s)
    } else {
        u32::from_le_bytes(s)
    })
}

/// A string at `at` (aligned), and where it ends.
fn read_string(b: &[u8], at: usize, big: bool) -> io::Result<(String, usize)> {
    let at = at.next_multiple_of(4);
    let len = read_u32(b, at, big)? as usize;
    let s = b
        .get(at + 4..at + 4 + len)
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    Ok((String::from_utf8_lossy(s).into_owned(), at + 4 + len + 1))
}

/// A message of the manager: its type, the fields and the body (as they
/// were read, the body at `body_at`), and the byte order.
struct Message {
    kind: u8,
    rest: Vec<u8>,
    fields_len: usize,
    big: bool,
}

impl Message {
    fn body_at(&self) -> usize {
        self.fields_len.next_multiple_of(8)
    }

    /// The string of the field `code` (the error name is 4, the member of
    /// a signal 3), empty if there is none.
    fn field(&self, code: u8) -> io::Result<String> {
        let (mut found, mut at) = (String::new(), 0);
        while at < self.fields_len {
            at = at.next_multiple_of(8);
            let this = *self
                .rest
                .get(at)
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
            let sig_len = *self.rest.get(at + 1).unwrap_or(&0) as usize;
            let sig = self.rest.get(at + 2..at + 2 + sig_len).unwrap_or_default();
            let value_at = at + 2 + sig_len + 1;
            match sig {
                b"s" | b"o" => {
                    let (s, end) = read_string(&self.rest, value_at, self.big)?;
                    if this == code {
                        found = s;
                    }
                    at = end;
                }
                b"u" => at = value_at.next_multiple_of(4) + 4,
                b"g" => {
                    let n = *self.rest.get(value_at).unwrap_or(&0) as usize;
                    at = value_at + 1 + n + 1;
                }
                _ => break,
            }
        }
        Ok(found)
    }
}

/// The next message of the manager.
fn read_one(r: &mut impl Read) -> io::Result<Message> {
    let mut fixed = [0u8; 16];
    r.read_exact(&mut fixed)?;
    // (the manager writes in the byte order of its host)
    let big = match fixed[0] {
        b'l' => false,
        b'B' => true,
        _ => return Err(io::Error::other("not a D-Bus message")),
    };
    let body_len = read_u32(&fixed, 4, big)? as usize;
    let fields_len = read_u32(&fixed, 12, big)? as usize;
    let total = fields_len.next_multiple_of(8) + body_len;
    if total > MAX_REPLY {
        return Err(io::Error::other("the answer of the manager is too big"));
    }
    let mut rest = vec![0u8; total];
    r.read_exact(&mut rest)?;
    Ok(Message {
        kind: fixed[1],
        rest,
        fields_len,
        big,
    })
}

/// Read the answer from `r`, after the signals that may come before it.
#[cfg(test)]
fn read_message(r: &mut impl Read) -> io::Result<Reply> {
    read_message_keeping(r, &mut Vec::new())
}

/// The most `JobRemoved` signals kept that came before the answer.
const MAX_EARLY_JOBS: usize = 64;

/// [`read_message`], keeping in `jobs` the `JobRemoved` signals that came
/// before the answer (a job that ended before the reply was read).
fn read_message_keeping(r: &mut impl Read, jobs: &mut Vec<Message>) -> io::Result<Reply> {
    let message = loop {
        let m = read_one(r)?;
        // a signal (the manager says what it does) is not the answer
        if m.kind != 4 {
            break m;
        }
        if jobs.len() < MAX_EARLY_JOBS && m.field(3)? == "JobRemoved" {
            jobs.push(m);
        }
    };
    match message.kind {
        // (the job path is the body: none in a reply that has no body)
        2 => Ok(Reply::Return(
            read_string(
                &message.rest[message.body_at().min(message.rest.len())..],
                0,
                message.big,
            )
            .map(|(s, _)| s)
            .unwrap_or_default(),
        )),
        3 => {
            // the message is the first string of the body
            let name = message.field(4)?;
            let text = read_string(&message.rest[message.body_at()..], 0, message.big)
                .map(|(s, _)| s)
                .unwrap_or_default();
            Ok(Reply::Error(name, text))
        }
        kind => Err(io::Error::other(format!("unexpected message type {kind}"))),
    }
}

/// The result of the job `job` if `m` is its `JobRemoved` signal: an error
/// if it did not end with `done`.
fn job_result(m: &Message, job: &str) -> io::Result<Option<()>> {
    if m.kind != 4 || m.field(3)? != "JobRemoved" {
        return Ok(None);
    }
    // (uint32 id, object job, string unit, string result)
    let body = m
        .rest
        .get(m.body_at()..)
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    let (path, end) = read_string(body, 4, m.big)?;
    if path != job {
        return Ok(None);
    }
    let (unit, end) = read_string(body, end, m.big)?;
    let (result, _) = read_string(body, end, m.big)?;
    match result.as_str() {
        "done" => Ok(Some(())),
        other => Err(io::Error::other(format!(
            "the manager's job for {unit} ended with `{other}`"
        ))),
    }
}

/// Block until the manager says the job `job` is done (`JobRemoved`, which
/// a private connection gets without subscribing; `early` are the ones
/// that came before the reply), at most until `deadline`: an error if it
/// did not end with `done`.  The other messages are read and dropped (the
/// connection is the caller's own and is closed after).
fn wait_job(s: &mut UnixStream, job: &str, early: &[Message], deadline: Instant) -> io::Result<()> {
    for m in early {
        if job_result(m, job)?.is_some() {
            return Ok(());
        }
    }
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("the manager's job {job} did not end in {TIMEOUT:?}"),
            ));
        }
        s.set_read_timeout(Some(left))?;
        let m = read_one(s).map_err(|e| match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => io::Error::new(
                io::ErrorKind::TimedOut,
                format!("the manager's job {job} did not end in {TIMEOUT:?}"),
            ),
            _ => e,
        })?;
        if job_result(&m, job)?.is_some() {
            return Ok(());
        }
    }
}

/// Send the call `msg` (made with serial 1) to the manager at `socket`; with
/// `wait`, return when the job the manager queued for it is done, else when
/// the answer is read.
fn call_at(socket: &Path, msg: Vec<u8>, wait: bool) -> io::Result<()> {
    let deadline = Instant::now() + TIMEOUT;
    let mut s = send_at(socket, msg)?;
    let mut early = Vec::new();
    match read_message_keeping(&mut s, &mut early)? {
        Reply::Return(job) if wait && !job.is_empty() => wait_job(&mut s, &job, &early, deadline),
        Reply::Return(_) => Ok(()),
        Reply::Error(name, message) => Err(ManagerError { name, message }.into()),
    }
}

/// Connect to the manager at `socket`, authenticate and send the call
/// `msg`: the connection, to read the answer from.
fn send_at(socket: &Path, msg: Vec<u8>) -> io::Result<UnixStream> {
    send_within(socket, msg, TIMEOUT)
}

/// [`send_at`], waiting at most `timeout` for each step.
fn send_within(socket: &Path, msg: Vec<u8>, timeout: Duration) -> io::Result<UnixStream> {
    let mut s = UnixStream::connect(socket).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("no service manager at {}: {e}", socket.display()),
        )
    })?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    // (the manager sees the user outside of a user namespace)
    let uid = velarx_base::ids::host_uid().map_err(io::Error::other)?;
    let hex: String = uid
        .to_string()
        .bytes()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut out = format!("\0AUTH EXTERNAL {hex}\r\nBEGIN\r\n").into_bytes();
    out.extend(msg);
    s.write_all(&out)?;
    // "OK <guid>\r\n" first
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while !line.ends_with(b"\r\n") {
        s.read_exact(&mut byte)?;
        line.push(byte[0]);
        if line.len() > 256 {
            return Err(io::Error::other(
                "the manager's authentication answer is too long",
            ));
        }
    }
    if !line.starts_with(b"OK ") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the manager refused the authentication: {}",
                String::from_utf8_lossy(&line).trim()
            ),
        ));
    }
    Ok(s)
}

/// The header flag that keeps the bus daemon from starting the service.
const NO_AUTO_START: u8 = 2;

/// The system bus daemon's socket.
const SYSTEM_BUS: &str = "/run/dbus/system_bus_socket";

/// The method `interface.member(args)` of the object `path` of the service
/// `destination` on the system bus, the arguments all strings; the service
/// is not started if it is not running.  The bus daemon wants a `Hello`
/// first, which is sent with the call.  An error the service answers is a
/// [`ManagerError`] (its D-Bus name and message); no bus daemon is the
/// `NotFound` or `ConnectionRefused` error of the socket.  The answer is
/// the first string of the reply (empty when it has none).
pub fn call_system_bus(
    destination: &str,
    path: &str,
    interface: &str,
    member: &str,
    args: &[&str],
    timeout: Duration,
) -> io::Result<String> {
    call_bus_at(
        Path::new(SYSTEM_BUS),
        destination,
        path,
        interface,
        member,
        args,
        timeout,
    )
}

/// [`call_system_bus`] on the bus daemon at `socket`.
fn call_bus_at(
    socket: &Path,
    destination: &str,
    path: &str,
    interface: &str,
    member: &str,
    args: &[&str],
    timeout: Duration,
) -> io::Result<String> {
    // (the bus daemon needs a name before it routes a call: the Hello
    // is serial 1, the call serial 2)
    let mut msg = call_to(
        1,
        &Target {
            destination: "org.freedesktop.DBus",
            flags: 0,
            path: "/org/freedesktop/DBus",
            interface: "org.freedesktop.DBus",
        },
        "Hello",
        "",
        &Writer::default(),
    );
    let mut body = Writer::default();
    for a in args {
        body.string(a);
    }
    msg.extend(call_to(
        2,
        &Target {
            destination,
            flags: NO_AUTO_START,
            path,
            interface,
        },
        member,
        &"s".repeat(args.len()),
        &body,
    ));
    let mut s = send_within(socket, msg, timeout)?;
    let mut answer = String::new();
    // (the answer of the Hello, then that of the call)
    for _ in 0..2 {
        match read_message_keeping(&mut s, &mut Vec::new())? {
            Reply::Error(name, message) => return Err(ManagerError { name, message }.into()),
            Reply::Return(text) => answer = text,
        }
    }
    Ok(answer)
}

/// The variant `property` of `interface` of the unit `unit` at the manager
/// at `socket`, and the order of its bytes.
fn unit_property_at(
    socket: &Path,
    unit: &str,
    interface: &str,
    property: &str,
) -> io::Result<(Vec<u8>, bool)> {
    let mut s = send_at(socket, get_property_call(1, unit, interface, property))?;
    let m = loop {
        let m = read_one(&mut s)?;
        // (a signal is not the answer)
        if m.kind != 4 {
            break m;
        }
    };
    let body = m.rest.get(m.body_at()..).unwrap_or_default();
    match m.kind {
        2 => Ok((body.to_vec(), m.big)),
        3 => Err(ManagerError {
            name: m.field(4)?,
            message: read_string(body, 0, m.big)
                .map(|(s, _)| s)
                .unwrap_or_default(),
        }
        .into()),
        kind => Err(io::Error::other(format!("unexpected message type {kind}"))),
    }
}

/// The boolean property `property` of `interface` of the unit `unit` at
/// the manager at `socket` (`Delegate` of `org.freedesktop.systemd1.Service`).
pub fn unit_bool_at(
    socket: &Path,
    unit: &str,
    interface: &str,
    property: &str,
) -> io::Result<bool> {
    let (body, big) = unit_property_at(socket, unit, interface, property)?;
    variant_bool(&body, big)
}

/// The string property `property` of `interface` of the unit `unit` at the
/// manager at `socket` (`OOMPolicy` of `org.freedesktop.systemd1.Service`).
pub fn unit_string_at(
    socket: &Path,
    unit: &str,
    interface: &str,
    property: &str,
) -> io::Result<String> {
    let (body, big) = unit_property_at(socket, unit, interface, property)?;
    variant_string(&body, big)
}

/// The string of a variant `s` at the start of `body`.
fn variant_string(body: &[u8], big: bool) -> io::Result<String> {
    let len = *body
        .first()
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))? as usize;
    if body.get(1..1 + len) != Some(b"s") {
        return Err(io::Error::other("the property is not a string"));
    }
    Ok(read_string(body, 2 + len, big)?.0)
}

/// The boolean of a variant `v` at the start of `body`.
fn variant_bool(body: &[u8], big: bool) -> io::Result<bool> {
    let len = *body
        .first()
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))? as usize;
    if body.get(1..1 + len) != Some(b"b") {
        return Err(io::Error::other("the property is not a boolean"));
    }
    Ok(read_u32(body, (2 + len).next_multiple_of(4), big)? != 0)
}

/// Ask the manager at `socket` for a transient unit `name` (`X.scope` or
/// `X.slice`) with `properties`; with `wait`, return when its job is done
/// (the processes are in the scope), else when the job is queued.
pub fn start_unit_at(
    socket: &Path,
    name: &str,
    properties: &[Property],
    wait: bool,
) -> io::Result<()> {
    call_at(socket, start_transient_unit(1, name, properties), wait)
}

/// Change `properties` of the unit `name` at the manager at `socket`.
pub fn set_properties_at(socket: &Path, name: &str, properties: &[Property]) -> io::Result<()> {
    call_at(socket, set_unit_properties(1, name, properties), false)
}

/// Stop the unit `name` at the manager at `socket`, and wait for it.
pub fn stop_unit_at(socket: &Path, name: &str) -> io::Result<()> {
    call_at(socket, stop_unit_call(1, name), true)
}

/// Wait until the manager at `socket` has no unit `unit` loaded any more
/// (`UnitRemoved`, which a private connection gets without subscribing),
/// at most `limit`; whether it is gone.  The signals come from the moment
/// of the connection on and the unit is asked for after it, so a removal
/// does not fall between.
pub fn wait_unit_gone(socket: &Path, unit: &str, limit: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + limit;
    let mut s = send_at(
        socket,
        get_property_call(1, unit, "org.freedesktop.systemd1.Unit", "ActiveState"),
    )?;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(false);
        }
        s.set_read_timeout(Some(left))?;
        let m = match read_one(&mut s) {
            Ok(m) => m,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(false)
            }
            Err(e) => return Err(e),
        };
        match m.kind {
            // an error: the unit is not loaded
            3 => return Ok(true),
            4 if m.field(3)? == "UnitRemoved" => {
                let body = m.rest.get(m.body_at()..).unwrap_or_default();
                if read_string(body, 0, m.big)?.0 == unit {
                    return Ok(true);
                }
            }
            _ => {}
        }
    }
}

/// An error the manager answered a call with: its D-Bus name and its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerError {
    pub name: String,
    pub message: String,
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.name, self.message)
    }
}

impl std::error::Error for ManagerError {}

impl From<ManagerError> for io::Error {
    fn from(e: ManagerError) -> Self {
        io::Error::other(e)
    }
}

/// The error of the manager `e` is, when it is one.
pub fn manager_error(e: &io::Error) -> Option<&ManagerError> {
    e.get_ref()?.downcast_ref()
}

/// Whether the error of a start says the unit is there already.
pub fn unit_exists(e: &io::Error) -> bool {
    manager_error(e).is_some_and(|m| m.name == UNIT_EXISTS)
}

/// The error of the manager for a name that is taken.
const UNIT_EXISTS: &str = "org.freedesktop.systemd1.UnitExists";

/// Whether the error of a property read says the manager has no such unit
/// loaded.
pub fn no_such_unit(e: &io::Error) -> bool {
    manager_error(e).is_some_and(|m| {
        matches!(
            m.name.as_str(),
            "org.freedesktop.systemd1.NoSuchUnit" | "org.freedesktop.DBus.Error.UnknownObject"
        )
    })
}

/// A scope `name` (`X.scope`) of the manager of the user, or the system's
/// (`system`), holding `pids`, collected when it ends or fails:
/// `systemd-run --scope --collect`.  With `wait` it returns when the
/// processes are in the scope, else when the manager has queued the job.
pub fn start_scope(
    system: bool,
    name: &str,
    description: &str,
    pids: &[u32],
    delegate: bool,
    slice: Option<&str>,
    wait: bool,
) -> io::Result<()> {
    let socket = manager_socket(system).map_err(io::Error::other)?;
    let mut props = vec![
        Property::Str("Description", description.to_string()),
        Property::Str("CollectMode", "inactive-or-failed".to_string()),
        Property::Pids(pids.to_vec()),
    ];
    if delegate {
        props.push(Property::Bool("Delegate", true));
    }
    if let Some(slice) = slice {
        props.push(Property::Str("Slice", slice.to_string()));
    }
    start_unit_at(&socket, &format!("{name}.scope"), &props, wait)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_unit_the_manager_does_not_have_is_told_by_the_name_of_the_error() {
        let refused = |name: &str, message: &str| {
            no_such_unit(
                &ManagerError {
                    name: name.into(),
                    message: message.into(),
                }
                .into(),
            )
        };
        assert!(refused(
            "org.freedesktop.systemd1.NoSuchUnit",
            "Unit x.scope not loaded."
        ));
        assert!(refused("org.freedesktop.DBus.Error.UnknownObject", ""));
        // the words of another error do not make it one
        assert!(!refused(UNIT_EXISTS, "org.freedesktop.systemd1.NoSuchUnit"));
        assert!(!no_such_unit(&io::Error::other(
            "org.freedesktop.systemd1.NoSuchUnit"
        )));
    }

    /// The call as systemd's `sd_bus` parses it: fields and body at their
    /// alignments, the length of every array without its padding.
    #[test]
    fn the_call_is_aligned_as_dbus_wants() {
        let m = start_transient_unit(
            7,
            "a.scope",
            &[
                Property::Str("Description", "d".into()),
                Property::Bool("Delegate", true),
                Property::Pids(vec![42, 43]),
            ],
        );
        assert_eq!(&m[..4], &[b'l', 1, 0, 1]);
        let body_len = u32::from_le_bytes(m[4..8].try_into().unwrap()) as usize;
        assert_eq!(u32::from_le_bytes(m[8..12].try_into().unwrap()), 7);
        let fields_len = u32::from_le_bytes(m[12..16].try_into().unwrap()) as usize;
        // the body starts at an 8 byte boundary after the fields
        let body_at = (16 + fields_len).next_multiple_of(8);
        assert_eq!(m.len(), body_at + body_len);
        let body = &m[body_at..];
        // "a.scope", "fail", then the properties array
        let (name, end) = read_string(body, 0, false).unwrap();
        assert_eq!(name, "a.scope");
        let (mode, end) = read_string(body, end, false).unwrap();
        assert_eq!(mode, "fail");
        let props_len = read_u32(body, end.next_multiple_of(4), false).unwrap() as usize;
        let props_at = (end.next_multiple_of(4) + 4).next_multiple_of(8);
        // the second array (units to start with it) is empty, at the end
        let aux_at = (props_at + props_len).next_multiple_of(4);
        assert_eq!(read_u32(body, aux_at, false).unwrap(), 0);
        assert_eq!(body.len(), (aux_at + 4).next_multiple_of(8));
        // the first property: "Description" as a string variant
        let (p, end) = read_string(body, props_at, false).unwrap();
        assert_eq!(p, "Description");
        assert_eq!(&body[end..end + 3], &[1, b's', 0]);
        let (v, _) = read_string(body, end + 3, false).unwrap();
        assert_eq!(v, "d");
        // the PIDs property is `au` holding both pids
        let tail = &body[props_at..props_at + props_len];
        let pos = tail.windows(4).position(|w| w == b"PIDs").unwrap();
        let sig_at = pos + 4 + 1;
        assert_eq!(&tail[sig_at..sig_at + 4], &[2, b'a', b'u', 0]);
        let arr = (sig_at + 4).next_multiple_of(4);
        assert_eq!(read_u32(tail, arr, false).unwrap(), 8);
        assert_eq!(read_u32(tail, arr + 4, false).unwrap(), 42);
        assert_eq!(read_u32(tail, arr + 8, false).unwrap(), 43);
    }

    /// `SetUnitProperties` and `StopUnit`: the signature in the header, the
    /// name, the flag and an array of properties with a byte array.
    #[test]
    fn the_other_calls_are_made_of_the_same_parts() {
        let m = set_unit_properties(
            3,
            "a.slice",
            &[
                Property::U64("MemoryMax", 7),
                Property::Bytes("AllowedCPUs", vec![0b101, 1]),
            ],
        );
        assert!(m.windows(7).any(|w| w == b"sba(sv)"));
        assert!(m.windows(17).any(|w| w == b"SetUnitProperties"));
        let body_len = u32::from_le_bytes(m[4..8].try_into().unwrap()) as usize;
        let fields_len = u32::from_le_bytes(m[12..16].try_into().unwrap()) as usize;
        let body_at = (16 + fields_len).next_multiple_of(8);
        assert_eq!(m.len(), body_at + body_len);
        let body = &m[body_at..];
        let (name, end) = read_string(body, 0, false).unwrap();
        assert_eq!(name, "a.slice");
        // runtime, then the array
        assert_eq!(read_u32(body, end.next_multiple_of(4), false).unwrap(), 1);
        let pos = body.windows(11).position(|w| w == b"AllowedCPUs").unwrap();
        // name, nul, the signature `ay`, the length, the bytes
        let sig_at = pos + 11 + 1;
        assert_eq!(&body[sig_at..sig_at + 4], &[2, b'a', b'y', 0]);
        assert_eq!(read_u32(body, sig_at + 4, false).unwrap(), 2);
        assert_eq!(&body[sig_at + 8..sig_at + 10], &[0b101, 1]);
        let stop = stop_unit_call(4, "a.slice");
        assert!(stop.windows(8).any(|w| w == b"StopUnit"));
        assert!(stop.windows(7).any(|w| w == b"replace"));
    }

    /// An `a(st)` property, compared with the message made by hand: the
    /// header of the variant, the length of the elements, each structure on
    /// an 8 byte boundary with its string and its `t`.
    #[test]
    fn a_device_limit_is_an_array_of_structures() {
        let mut w = Writer::default();
        w.property(&Property::Devices(
            "IOWeight",
            vec![("/dev/b".into(), 5), ("/d".into(), 1 << 40)],
        ));
        let mut want = Vec::new();
        // the name: length, bytes, nul
        want.extend_from_slice(&8u32.to_le_bytes());
        want.extend_from_slice(b"IOWeight\0");
        // the signature of the variant
        want.extend_from_slice(&[5]);
        want.extend_from_slice(b"a(st)\0");
        // (offset 20 here) the length of the elements, which start at 24
        want.extend_from_slice(&40u32.to_le_bytes());
        want.extend_from_slice(&6u32.to_le_bytes());
        want.extend_from_slice(b"/dev/b\0");
        want.extend_from_slice(&[0; 5]);
        want.extend_from_slice(&5u64.to_le_bytes());
        want.extend_from_slice(&2u32.to_le_bytes());
        want.extend_from_slice(b"/d\0");
        want.extend_from_slice(&[0; 1]);
        want.extend_from_slice(&(1u64 << 40).to_le_bytes());
        assert_eq!(w.0, want);
        // none: an empty array (a limit taken away)
        let mut w = Writer::default();
        w.property(&Property::Devices("IOWeight", Vec::new()));
        assert_eq!(w.0.len(), 24);
        assert_eq!(&w.0[20..], &[0; 4]);
    }

    /// A `t` property (a limit): its signature, and the value on an 8 byte
    /// boundary of the message.
    #[test]
    fn a_limit_is_a_u64_variant() {
        let m = start_transient_unit(
            1,
            "a.scope",
            &[
                Property::Bool("Delegate", true),
                Property::U64("MemoryMax", (1 << 33) + 5),
            ],
        );
        let name_at = m.windows(9).position(|w| w == b"MemoryMax").unwrap();
        let sig_at = name_at + 9 + 1;
        assert_eq!(&m[sig_at..sig_at + 3], &[1, b't', 0]);
        let value_at = (sig_at + 3).next_multiple_of(8);
        assert_eq!(
            u64::from_le_bytes(m[value_at..value_at + 8].try_into().unwrap()),
            (1 << 33) + 5
        );
    }

    /// A fake manager answers an error and then a return.
    #[test]
    fn the_answers_are_read() {
        // method return, no fields, no body
        let ret = [b'l', 2, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            read_message(&mut &ret[..]).unwrap(),
            Reply::Return(String::new())
        );
        // an error: field 4 (error name) and a body with the message
        let mut f = Writer::default();
        f.0.extend_from_slice(&[4, 1, b's', 0]);
        f.string("org.freedesktop.systemd1.UnitExists");
        let fields_len = f.0.len() as u32;
        let mut b = Writer::default();
        b.string("Unit a.scope already exists.");
        let mut m = vec![b'l', 3, 1, 1];
        m.extend((b.0.len() as u32).to_le_bytes());
        m.extend(2u32.to_le_bytes());
        m.extend(fields_len.to_le_bytes());
        m.extend(&f.0);
        while !m.len().is_multiple_of(8) {
            m.push(0);
        }
        m.extend(&b.0);
        assert_eq!(
            read_message(&mut &m[..]).unwrap(),
            Reply::Error(
                "org.freedesktop.systemd1.UnitExists".into(),
                "Unit a.scope already exists.".into()
            )
        );
    }

    #[test]
    fn a_unit_that_exists_is_told_by_the_name_of_the_error() {
        let exists = |name: &str, message: &str| {
            unit_exists(
                &ManagerError {
                    name: name.into(),
                    message: message.into(),
                }
                .into(),
            )
        };
        assert!(exists(UNIT_EXISTS, "Unit a.scope already exists."));
        // the words of another error do not make it one
        assert!(!exists(
            "org.freedesktop.systemd1.NoSuchUnit",
            "org.freedesktop.systemd1.UnitExists"
        ));
        assert!(!unit_exists(&io::Error::other(UNIT_EXISTS)));
    }

    /// Signals before the answer are skipped, a manager on a big endian
    /// host is understood, and what is not D-Bus is an error.
    #[test]
    fn signals_and_byte_orders() {
        // a signal with 8 bytes of fields and 4 of body, then a big endian
        // method return
        let mut m = vec![b'l', 4, 1, 1, 4, 0, 0, 0, 9, 0, 0, 0, 8, 0, 0, 0];
        m.extend([0u8; 12]);
        m.extend([b'B', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0]);
        assert_eq!(
            read_message(&mut &m[..]).unwrap(),
            Reply::Return(String::new())
        );
        // a big endian error: name and message
        let mut f = vec![4, 1, b's', 0];
        f.extend(5u32.to_be_bytes());
        f.extend(b"a.b.C\0");
        let mut m = vec![b'B', 3, 1, 1];
        m.extend(7u32.to_be_bytes());
        m.extend(3u32.to_be_bytes());
        m.extend((f.len() as u32).to_be_bytes());
        m.extend(&f);
        while !m.len().is_multiple_of(8) {
            m.push(0);
        }
        m.extend(2u32.to_be_bytes());
        m.extend(b"no\0");
        assert_eq!(
            read_message(&mut &m[..]).unwrap(),
            Reply::Error("a.b.C".into(), "no".into())
        );
        assert!(read_message(&mut &[b'x'; 16][..]).is_err());
        // a length beyond the limit is refused before anything is allocated
        let huge = [
            b'l', 2, 1, 1, 0xff, 0xff, 0xff, 0xff, 1, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(read_message(&mut &huge[..]).is_err());
        // a message cut short is an error, not a panic
        let cut = [b'l', 3, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 64, 0, 0, 0, 4, 1];
        assert!(read_message(&mut &cut[..]).is_err());
    }

    /// The conversation over a socket: authentication, the call, an answer.
    #[test]
    fn a_fake_manager_is_asked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            // the client sends everything at once; the call ends the data
            while !seen.windows(7).any(|w| w == b"a.scope") {
                let n = c.read(&mut buf).unwrap();
                seen.extend_from_slice(&buf[..n]);
            }
            c.write_all(b"OK 0123456789abcdef\r\n").unwrap();
            c.write_all(&[b'l', 2, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0])
                .unwrap();
            seen
        });
        start_unit_at(&path, "a.scope", &[Property::Pids(vec![1])], false).unwrap();
        let seen = server.join().unwrap();
        assert!(seen.starts_with(b"\0AUTH EXTERNAL "));
        assert!(seen.windows(7).any(|w| w == b"BEGIN\r\n"));
    }

    /// The bus daemon wants a `Hello` before the call, and the call must
    /// not start the service; the error of the service comes back by name.
    #[test]
    fn a_call_on_the_bus_says_hello_first_and_answers_by_error_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bus");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            while !seen.windows(5).any(|w| w == b"trust") {
                let n = c.read(&mut buf).unwrap();
                seen.extend_from_slice(&buf[..n]);
            }
            c.write_all(b"OK 0123456789abcdef\r\n").unwrap();
            let mut name = Writer::default();
            name.string(":1.7");
            c.write_all(&message(2, &[], &name.0)).unwrap();
            // (the bus announces the name it gave)
            c.write_all(&message(4, &[(3, "s", "NameAcquired")], &name.0))
                .unwrap();
            let mut text = Writer::default();
            text.string("ZONE_CONFLICT: x");
            c.write_all(&message(
                3,
                &[(4, "s", "org.fedoraproject.FirewallD1.Exception")],
                &text.0,
            ))
            .unwrap();
            seen
        });
        let e = call_bus_at(
            &path,
            "org.example.Service",
            "/org/example",
            "org.example.Zone",
            "addSource",
            &["trust", "10.0.0.0/24"],
            Duration::from_secs(5),
        )
        .unwrap_err();
        let err = manager_error(&e).unwrap();
        assert_eq!(err.name, "org.fedoraproject.FirewallD1.Exception");
        assert_eq!(err.message, "ZONE_CONFLICT: x");
        let seen = server.join().unwrap();
        let at = |needle: &[u8]| seen.windows(needle.len()).position(|w| w == needle);
        let (hello, call) = (at(b"Hello").unwrap(), at(b"addSource").unwrap());
        assert!(hello < call);
        // the second message of the pipe is the call: its flags byte
        // (NO_AUTO_START) follows the first message
        let begin = at(b"BEGIN\r\n").unwrap() + 7;
        assert_eq!(&seen[begin..begin + 4], &[b'l', 1, 0, 1]);
        let first_len = 16
            + (u32::from_le_bytes(seen[begin + 12..begin + 16].try_into().unwrap()) as usize)
                .next_multiple_of(8);
        assert_eq!(
            &seen[begin + first_len..begin + first_len + 4],
            &[b'l', 1, NO_AUTO_START, 1]
        );
    }

    /// The answer of a call is the first string of the reply to it, not
    /// the name the bus gave for the `Hello`.
    #[test]
    fn a_call_on_the_bus_answers_the_string_of_its_reply() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bus");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            while !seen.windows(15).any(|w| w == b"getZoneOfSource") {
                let n = c.read(&mut buf).unwrap();
                seen.extend_from_slice(&buf[..n]);
            }
            c.write_all(b"OK 0123456789abcdef\r\n").unwrap();
            let mut name = Writer::default();
            name.string(":1.7");
            c.write_all(&message(2, &[], &name.0)).unwrap();
            let mut zone = Writer::default();
            zone.string("trusted");
            c.write_all(&message(2, &[], &zone.0)).unwrap();
        });
        let zone = call_bus_at(
            &path,
            "org.example.Service",
            "/org/example",
            "org.example.Zone",
            "getZoneOfSource",
            &["10.0.0.0/24"],
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(zone, "trusted");
        server.join().unwrap();
    }

    #[test]
    fn a_unit_has_an_object_path() {
        assert_eq!(
            unit_path("velarx-engine.service"),
            "/org/freedesktop/systemd1/unit/velarx_2dengine_2eservice"
        );
        assert_eq!(
            unit_path("1a_b.scope"),
            "/org/freedesktop/systemd1/unit/_31a_5fb_2escope"
        );
    }

    /// `Get` of a property: the call to the unit's object, a boolean in a
    /// variant read back.
    #[test]
    fn a_property_of_a_unit_is_asked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let answer = |delegate: u32| {
            let mut body = Writer::default();
            body.signature("b");
            body.u32(delegate);
            message(2, &[], &body.0)
        };
        let replies = vec![
            answer(1),
            answer(0),
            message(3, &[(4, "s", "org.freedesktop.systemd1.NoSuchUnit")], &{
                let mut b = Writer::default();
                b.string("Unit x.service not loaded.");
                b.0
            }),
        ];
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for reply in replies {
                let (mut c, _) = listener.accept().unwrap();
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                while !got.windows(8).any(|w| w == b"Delegate") {
                    let n = c.read(&mut buf).unwrap();
                    got.extend_from_slice(&buf[..n]);
                }
                c.write_all(b"OK 0123456789abcdef\r\n").unwrap();
                c.write_all(&reply).unwrap();
                seen = got;
            }
            seen
        });
        let ask = || {
            unit_bool_at(
                &path,
                "x.service",
                "org.freedesktop.systemd1.Service",
                "Delegate",
            )
        };
        assert!(ask().unwrap());
        assert!(!ask().unwrap());
        let refused = ask().unwrap_err();
        assert!(manager_error(&refused).is_some_and(|m| m.name.ends_with("NoSuchUnit")));
        let seen = server.join().unwrap();
        // the object of the unit, the interface of the properties
        for part in [
            &b"/org/freedesktop/systemd1/unit/x_2eservice"[..],
            b"org.freedesktop.DBus.Properties",
            b"Get",
        ] {
            assert!(
                seen.windows(part.len()).any(|w| w == part),
                "{}",
                String::from_utf8_lossy(part)
            );
        }
        // a property that is not a boolean is not read as one
        let mut body = Writer::default();
        body.signature("s");
        body.string("yes");
        assert!(variant_bool(&body.0, false).is_err());
        // a string is read as one, and nothing else is
        assert_eq!(variant_string(&body.0, false).unwrap(), "yes");
        let mut other = Writer::default();
        other.signature("b");
        other.u32(1);
        assert!(variant_string(&other.0, false).is_err());
    }

    /// The wait for a unit to go ends with the signal of its removal (not
    /// with that of another unit), at once for a unit that is not loaded,
    /// and with the limit when nothing comes.
    #[test]
    fn a_unit_is_waited_for_until_the_manager_drops_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let answer = {
            let mut body = Writer::default();
            body.signature("s");
            body.string("inactive");
            message(2, &[], &body.0)
        };
        let removed = |unit: &str| {
            let mut body = Writer::default();
            body.string(unit);
            body.string("/org/freedesktop/systemd1/unit/x");
            message(4, &[(3, "s", "UnitRemoved")], &body.0)
        };
        let not_loaded = message(
            3,
            &[(4, "s", "org.freedesktop.DBus.Error.UnknownObject")],
            &{
                let mut b = Writer::default();
                b.string("not loaded");
                b.0
            },
        );
        let scripts: Vec<Vec<Vec<u8>>> = vec![
            vec![answer.clone(), removed("other.scope"), removed("a.scope")],
            vec![not_loaded],
            vec![answer],
        ];
        let server = std::thread::spawn(move || {
            let mut held = Vec::new();
            for script in scripts {
                let (mut c, _) = listener.accept().unwrap();
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                while !got.windows(3).any(|w| w == b"Get") {
                    let n = c.read(&mut buf).unwrap();
                    got.extend_from_slice(&buf[..n]);
                }
                c.write_all(b"OK 0123456789abcdef\r\n").unwrap();
                for m in script {
                    c.write_all(&m).unwrap();
                }
                held.push(c);
            }
            held
        });
        let limit = Duration::from_secs(60);
        assert!(wait_unit_gone(&path, "a.scope", limit).unwrap());
        assert!(wait_unit_gone(&path, "a.scope", limit).unwrap());
        assert!(!wait_unit_gone(&path, "a.scope", Duration::from_millis(50)).unwrap());
        drop(server.join().unwrap());
    }

    /// A little endian message of `kind` with the string fields `fields`
    /// (code, signature, value) and `body`.
    fn message(kind: u8, fields: &[(u8, &str, &str)], body: &[u8]) -> Vec<u8> {
        let mut f = Writer::default();
        for (code, sig, v) in fields {
            f.align(8);
            f.0.push(*code);
            f.signature(sig);
            f.string(v);
        }
        let mut m = vec![b'l', kind, 1, 1];
        m.extend((body.len() as u32).to_le_bytes());
        m.extend(2u32.to_le_bytes());
        m.extend((f.0.len() as u32).to_le_bytes());
        m.extend(&f.0);
        while !m.len().is_multiple_of(8) {
            m.push(0);
        }
        m.extend(body);
        m
    }

    fn job_removed(job: &str, result: &str) -> Vec<u8> {
        let mut body = Writer::default();
        body.u32(7);
        body.string(job);
        body.string("a.scope");
        body.string(result);
        message(4, &[(3, "s", "JobRemoved")], &body.0)
    }

    /// A manager that answers the call with the job `/job/1`, then says
    /// what `after` has; whether the call returned before the job ended.
    fn start_with(after: Vec<Vec<u8>>, wait: bool) -> (io::Result<()>, bool) {
        start_with_early(vec![], after, wait)
    }

    /// [`start_with`], with `before` sent before the reply.
    fn start_with_early(
        before: Vec<Vec<u8>>,
        after: Vec<Vec<u8>>,
        wait: bool,
    ) -> (io::Result<()>, bool) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            while !seen.windows(7).any(|w| w == b"a.scope") {
                let n = c.read(&mut buf).unwrap();
                seen.extend_from_slice(&buf[..n]);
            }
            c.write_all(b"OK 0123456789abcdef\r\n").unwrap();
            for m in before {
                c.write_all(&m).unwrap();
            }
            let mut body = Writer::default();
            body.string("/job/1");
            c.write_all(&message(2, &[], &body.0)).unwrap();
            // the job ends when the test says so
            rx.recv().unwrap();
            for m in after {
                c.write_all(&m).unwrap();
            }
        });
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let client = std::thread::spawn(move || {
            let r = start_unit_at(&path, "a.scope", &[Property::Pids(vec![1])], wait);
            done_tx.send(()).unwrap();
            r
        });
        // (the call returns by itself without wait: nothing is sent first)
        let early = !wait && done_rx.recv().is_ok();
        tx.send(()).unwrap();
        let r = client.join().unwrap();
        server.join().unwrap();
        (r, early)
    }

    #[test]
    fn the_start_waits_for_its_job() {
        let (r, _) = start_with(
            vec![
                job_removed("/job/2", "failed"),
                job_removed("/job/1", "done"),
            ],
            true,
        );
        r.unwrap();
        let (r, _) = start_with(vec![job_removed("/job/1", "failed")], true);
        assert!(r.unwrap_err().to_string().contains("failed"));
        // a job that ended before the reply was read is not waited for
        // again (nothing comes after the reply here)
        let (r, _) = start_with_early(vec![job_removed("/job/1", "done")], vec![], true);
        r.unwrap();
        // the job is not waited for when not asked
        let (r, returned_first) = start_with(vec![], false);
        r.unwrap();
        assert!(returned_first, "it waited for a job it was not asked to");
    }
}
