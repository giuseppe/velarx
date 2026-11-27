// SPDX-License-Identifier: Apache-2.0
//! `velarx-dir`: the fetcher of a directory of items named by their digests
//! (`velarx_content::dir_fetch`), a process of its own for the engine that
//! uses it, confined as the other fetchers are
//! ([`velarx_sandbox::fetch::Role::Dir`]): it reads that directory, writes
//! beneath the staging it was handed, opens no socket of the network and
//! executes nothing.  It links no registry or HTTP code.
//!
//! `--name NAME --dir PATH --varlink-fd N --config-fd N --staging-fd N`:
//! the one connection of the engine that started it is `--varlink-fd`; it
//! leaves when that connection and every one it handed out are closed.
//!
//! `--origin --varlink-fd N --config-fd N --staging-fd N`: the origin of a
//! pull whose source is a path (`velarx_content::dir_origin`, confined as
//! [`velarx_sandbox::fetch::Role::Dir`]) for one pull.  It learns its origin
//! from `Open` (the scheme and the selector of the source, the directory or
//! the file as the `target` descriptor) and confines itself there: it reads
//! what it was handed, writes beneath the staging, and nowhere else.
//!
//! `--push --varlink-fd N --config-fd N`: the pusher of a path
//! (`velarx_content::dir_push`, confined as
//! [`velarx_sandbox::fetch::Role::DirPush`]) for one push.  It learns its
//! destination from `Open` (the scheme says `oci:`, `dir:` or `oci-archive:`,
//! the `target` descriptor is the directory or the file) and confines itself
//! there: it writes beneath that directory (the file, for an archive) and
//! nowhere else.  `--config-fd` is a
//! [`velarx_content::list::HelperSettings`].

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use velarx_content::activation::{IdleExit, Limits};

use velarx_content::list::HelperSettings;

fn main() -> anyhow::Result<()> {
    let startup = velarx_sys::fd::Startup::take().expect("main is the first to take it");
    velarx_base::buildinfo::set(env!("VELARX_GIT_COMMIT"), env!("VELARX_BUILD_TIME"));
    if let Some(line) =
        velarx_base::buildinfo::version_line("velarx-dir", env!("CARGO_PKG_VERSION"))
    {
        println!("{line}");
        return Ok(());
    }
    velarx_wire::proctitle::set("velarx-dir");
    velarx_wire::logging::init("warn", "text");
    let args = Args::parse(std::env::args_os().skip(1))?;
    match args.mode {
        Mode::Push => serve_push(&args, &startup),
        Mode::Origin => serve_origin(&args, &startup),
        Mode::Dir => serve(&args, &startup),
    }
}

/// What a process of velarx-dir is: the fetcher of a directory, the origin
/// of a path or the pusher of a path.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Dir,
    Origin,
    Push,
}

/// The arguments of the three modes.
struct Args {
    mode: Mode,
    name: Option<String>,
    dir: Option<PathBuf>,
    varlink: Option<i32>,
    config: Option<i32>,
    staging: Option<i32>,
    /// `--self-test`: the scheme to confine for (none in the dir mode)
    self_test: Option<String>,
}

impl Args {
    fn parse(args: impl Iterator<Item = std::ffi::OsString>) -> anyhow::Result<Self> {
        let mut parsed = Self {
            mode: Mode::Dir,
            name: None,
            dir: None,
            varlink: None,
            config: None,
            staging: None,
            self_test: None,
        };
        let mut args = args;
        while let Some(arg) = args.next() {
            let mut value = || {
                args.next()
                    .ok_or_else(|| anyhow::anyhow!("{} needs a value", arg.to_string_lossy()))
            };
            let mut number =
                || -> anyhow::Result<Option<i32>> { Ok(Some(value()?.to_string_lossy().parse()?)) };
            match arg.to_str() {
                Some("--push") => parsed.mode = Mode::Push,
                Some("--origin") => parsed.mode = Mode::Origin,
                Some("--name") => parsed.name = Some(value()?.to_string_lossy().into_owned()),
                Some("--dir") => parsed.dir = Some(PathBuf::from(value()?)),
                Some("--varlink-fd") => parsed.varlink = number()?,
                Some("--config-fd") => parsed.config = number()?,
                Some("--staging-fd") => parsed.staging = number()?,
                Some("--self-test") if parsed.mode == Mode::Dir => {
                    parsed.self_test = Some(String::new())
                }
                Some("--self-test") => {
                    parsed.self_test = Some(value()?.to_string_lossy().into_owned())
                }
                _ => anyhow::bail!("unknown argument {}", arg.to_string_lossy()),
            }
        }
        Ok(parsed)
    }

    /// The descriptor `what` (`fd`, which the arguments gave) this process
    /// was started with.
    fn adopt(
        &self,
        startup: &velarx_sys::fd::Startup,
        what: &str,
        fd: Option<i32>,
    ) -> anyhow::Result<std::os::fd::OwnedFd> {
        let mode = match self.mode {
            Mode::Dir => "dir",
            Mode::Origin => "origin",
            Mode::Push => "push",
        };
        let fd = fd.ok_or_else(|| anyhow::anyhow!("{mode} needs --{what}-fd"))?;
        startup
            .adopt(fd)
            .ok_or_else(|| anyhow::anyhow!("the {what} descriptor {fd} is not open"))
    }

    /// The process is for one connection: the descriptors it was handed are
    /// claimed, the others closed and the process hardened.
    fn start(&self, startup: &velarx_sys::fd::Startup) -> anyhow::Result<Started> {
        let stream =
            std::os::unix::net::UnixStream::from(self.adopt(startup, "varlink", self.varlink)?);
        let config = self.adopt(startup, "config", self.config)?;
        startup.close_range(3, u32::MAX);
        velarx_base::hardening::harden()?;
        let settings = velarx_content::list::settings_from_fd(config)?;
        let idle = IdleExit {
            after: Duration::from_secs(settings.services.first_call_secs),
            socket: None,
            last: true,
            lock: None,
        };
        let limits = Limits::of(&settings.services);
        Ok(Started {
            stream,
            settings,
            idle,
            limits,
        })
    }
}

/// What a process serves with.
struct Started {
    stream: std::os::unix::net::UnixStream,
    settings: HelperSettings,
    idle: IdleExit,
    limits: Limits,
}

/// What confines the pusher of `mode` to its destination `dest`: the
/// directory it writes beneath (an archive: nothing; it writes the file it
/// holds open).
fn push_reach(
    mode: velarx_content::dir_push::Mode,
    dest: &std::os::fd::OwnedFd,
) -> anyhow::Result<velarx_sandbox::fetch::Reach> {
    let mut reach = velarx_sandbox::fetch::dir_push_reach();
    if mode.is_directory() {
        reach.staging = Some(Arc::new(rustix::io::dup(dest)?));
    }
    Ok(reach)
}

/// `--push`: serve the pusher of one destination.  The destination is what
/// `Open` says (the scheme of `destination` and the `target` descriptor),
/// and the process confines itself there, the only thread it has.
fn serve_push(args: &Args, startup: &velarx_sys::fd::Startup) -> anyhow::Result<()> {
    use velarx_content::dir_push::{DirPush, Mode};
    if let Some(scheme) = &args.self_test {
        // (the test hook: the destination of the scheme is the descriptor 5)
        let mode = Mode::of_scheme(scheme)
            .ok_or_else(|| anyhow::anyhow!("--self-test needs oci:, dir: or oci-archive:"))?;
        let dest = args.adopt(startup, "target", Some(5))?;
        startup.close_range(3, u32::MAX);
        return try_push_confinement(mode, dest);
    }
    let started = args.start(startup)?;
    let pusher = DirPush::new(Box::new(|mode, dest| {
        let reach = push_reach(mode, dest).map_err(|e| e.to_string())?;
        velarx_sandbox::fetch::enter(&reach, velarx_sandbox::fetch::Role::DirPush)
            .map(|_| ())
            .map_err(|e| format!("the directory pusher cannot confine itself: {e}"))
    }));
    Ok(velarx_content::serve_fetch::run_one_single_thread(
        started.stream,
        Arc::new(pusher),
        started.idle,
        started.limits,
    )?)
}

/// `--push --self-test SCHEME`: confine this process as the pusher of the
/// destination on descriptor 5 and print what it may and may not do as JSON
/// `[[what, as it should be], ...]`.
fn try_push_confinement(
    mode: velarx_content::dir_push::Mode,
    dest: std::os::fd::OwnedFd,
) -> anyhow::Result<()> {
    let reach = push_reach(mode, &dest)?;
    let staging = reach.staging.clone();
    let socket = match &staging {
        Some(dir) => {
            let socket =
                velarx_sys::fd::proc_path(&**dir).join(velarx_sandbox::fetch::PROBE_SOCKET);
            Some((std::os::unix::net::UnixListener::bind(&socket)?, socket))
        }
        None => None,
    };
    velarx_sandbox::fetch::enter(&reach, velarx_sandbox::fetch::Role::DirPush)
        .map_err(|e| anyhow::anyhow!("the directory pusher cannot confine itself: {e}"))?;
    let mut results = match (&staging, mode.is_directory()) {
        (Some(dir), true) => velarx_sandbox::fetch::probes(
            &rustix::io::dup(&**dir)?,
            socket.as_ref().map(|(_, s)| s.as_path()),
        ),
        _ => velarx_sandbox::fetch::refusals(None),
    };
    // (an archive's file is written to: the descriptor is open; nothing is
    // opened by a name)
    const PROBE: &str = "/var/tmp/.velarx-push-probe";
    let made = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(PROBE);
    results.push((
        "creates no file by a name".into(),
        made.as_ref()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied),
    ));
    if made.is_ok() {
        let _ = std::fs::remove_file(PROBE);
    }
    if !mode.is_directory() {
        let mut file = std::fs::File::from(dest);
        results.push((
            "writes the file it was handed".into(),
            std::io::Write::write_all(&mut file, b"x").is_ok(),
        ));
    }
    if let (Some(dir), Some((listener, _))) = (&staging, socket) {
        drop(listener);
        let _ = rustix::fs::unlinkat(
            &**dir,
            velarx_sandbox::fetch::PROBE_SOCKET,
            rustix::fs::AtFlags::empty(),
        );
    }
    println!("{}", serde_json::to_string(&results)?);
    Ok(())
}

/// What confines the origin of `scheme` to its target `target`: the runtime's
/// files, the directory (for a layout, read), and the staging.
fn origin_reach(
    _scheme: velarx_content::origin::PathScheme,
    target: &std::os::fd::OwnedFd,
    staging: &Arc<std::os::fd::OwnedFd>,
) -> anyhow::Result<velarx_sandbox::fetch::Reach> {
    let mut reach = velarx_sandbox::fetch::dir_origin_reach();
    reach.staging = Some(staging.clone());
    // (`archive:` and `rootfs:` are either kind: a directory is read beneath,
    // a file is read from the descriptor)
    let is_directory = rustix::fs::FileType::from_raw_mode(rustix::fs::fstat(target)?.st_mode)
        == rustix::fs::FileType::Directory;
    if is_directory {
        reach.origin = Some(Arc::new(rustix::io::dup(target)?));
    }
    Ok(reach)
}

/// `--origin`: serve the origin of one path.  The path is what `Open` says
/// (the scheme and the selector of the source, the `target` descriptor), and
/// the process confines itself there, the only thread it has.
fn serve_origin(args: &Args, startup: &velarx_sys::fd::Startup) -> anyhow::Result<()> {
    use velarx_content::origin::PathScheme;
    let staging = Arc::new(args.adopt(startup, "staging", args.staging)?);
    if let Some(scheme) = &args.self_test {
        // (the test hook: the origin of the scheme is the descriptor 5)
        let scheme = PathScheme::of(scheme.trim_end_matches(':')).ok_or_else(|| {
            anyhow::anyhow!(
                "--self-test needs a scheme: oci, dir, oci-archive, docker-archive, docker-daemon, rootfs or archive"
            )
        })?;
        let target = args.adopt(startup, "target", Some(5))?;
        startup.close_range(3, u32::MAX);
        return try_origin_confinement(scheme, target, staging);
    }
    let started = args.start(startup)?;
    velarx_base::hardening::limit_file_size(started.settings.max_file_bytes)?;
    let origin = velarx_content::dir_origin::DirOrigin::new(
        Box::new({
            let staging = staging.clone();
            move |scheme, target| {
                let target = rustix::io::dup(target).map_err(|e| e.to_string())?;
                let reach = origin_reach(scheme, &target, &staging).map_err(|e| e.to_string())?;
                velarx_sandbox::fetch::enter(&reach, velarx_sandbox::fetch::Role::Dir)
                    .map(|_| ())
                    .map_err(|e| format!("the directory origin cannot confine itself: {e}"))
            }
        }),
        started.settings,
        Arc::new(std::fs::File::from(rustix::io::dup(&*staging)?)),
    );
    Ok(velarx_content::serve_fetch::run_one_single_thread(
        started.stream,
        origin,
        started.idle,
        started.limits,
    )?)
}

/// `--origin --self-test SCHEME`: confine this process as the origin of the
/// path on descriptor 5 with the staging, try what that allows and refuses
/// and print the results as JSON `[[what, as it should be], ...]`.
fn try_origin_confinement(
    scheme: velarx_content::origin::PathScheme,
    target: std::os::fd::OwnedFd,
    staging: Arc<std::os::fd::OwnedFd>,
) -> anyhow::Result<()> {
    let reach = origin_reach(scheme, &target, &staging)?;
    let socket = velarx_sys::fd::proc_path(&*staging).join(velarx_sandbox::fetch::PROBE_SOCKET);
    let listener = std::os::unix::net::UnixListener::bind(&socket)?;
    velarx_sandbox::fetch::enter(&reach, velarx_sandbox::fetch::Role::Dir)
        .map_err(|e| anyhow::anyhow!("the directory origin cannot confine itself: {e}"))?;
    let mut results = velarx_sandbox::fetch::probes(&staging, Some(&socket));
    let mut file = std::fs::File::from(target);
    if file.metadata()?.is_dir() {
        results.push((
            "reads the directory it was handed".into(),
            rustix::fs::Dir::read_from(&file).is_ok_and(|d| d.count() > 0),
        ));
    } else {
        let mut head = [0u8; 1];
        results.push((
            "reads the file it was handed".into(),
            std::io::Read::read(&mut file, &mut head).is_ok(),
        ));
    }
    results.push((
        "opens no file outside its origin".into(),
        std::fs::File::open("/etc/passwd").is_err() && std::fs::read_dir("/var").is_err(),
    ));
    results.push((
        "writes nothing in its origin".into(),
        !file.metadata()?.is_dir()
            || std::fs::File::create("/proc/self/fd/5/.velarx-probe").is_err(),
    ));
    drop(listener);
    let _ = rustix::fs::unlinkat(
        &*staging,
        velarx_sandbox::fetch::PROBE_SOCKET,
        rustix::fs::AtFlags::empty(),
    );
    println!("{}", serde_json::to_string(&results)?);
    Ok(())
}

fn serve(args: &Args, startup: &velarx_sys::fd::Startup) -> anyhow::Result<()> {
    let (Some(name), Some(dir)) = (&args.name, args.dir.clone()) else {
        anyhow::bail!("dir needs --name and --dir");
    };
    let staging = Arc::new(args.adopt(startup, "staging", args.staging)?);
    if args.self_test.is_some() {
        startup.close_range(3, u32::MAX);
        return try_confinement(&dir, staging);
    }
    let started = args.start(startup)?;
    velarx_base::hardening::limit_file_size(started.settings.max_file_bytes)?;
    let mut reach = velarx_sandbox::fetch::dir_reach(&dir);
    reach.staging = Some(staging);
    velarx_sandbox::fetch::enter(&reach, velarx_sandbox::fetch::Role::Dir)
        .map_err(|e| anyhow::anyhow!("the directory fetcher cannot confine itself: {e}"))?;
    // (the calls run on this runtime; the connection is served by the thread
    // that runs it)
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("dir-fetcher")
        .enable_all()
        .build()?;
    let endpoint = {
        let _on = runtime.enter();
        velarx_content::serve_fetch::FetchEndpoint::new(velarx_content::dir_fetch::DirFetch::new(
            name, dir,
        ))
    };
    Ok(velarx_content::serve_fetch::run_one_blocking(
        started.stream,
        endpoint,
        started.idle,
        started.limits,
    )?)
}

/// `--self-test`: confine this process as the directory fetcher of `dir`
/// with `staging`, try what that allows and refuses and print the results as
/// JSON `[[what, as it should be], ...]`; nothing is served.
fn try_confinement(
    dir: &std::path::Path,
    staging: Arc<std::os::fd::OwnedFd>,
) -> anyhow::Result<()> {
    let mut reach = velarx_sandbox::fetch::dir_reach(dir);
    reach.staging = Some(staging.clone());
    // (a socket with a name, bound before the confinement: the confined
    // process may not connect to it)
    let socket = velarx_sys::fd::proc_path(&*staging).join(velarx_sandbox::fetch::PROBE_SOCKET);
    let listener = std::os::unix::net::UnixListener::bind(&socket)?;
    velarx_sandbox::fetch::enter(&reach, velarx_sandbox::fetch::Role::Dir)
        .map_err(|e| anyhow::anyhow!("the directory fetcher cannot confine itself: {e}"))?;
    let mut results = velarx_sandbox::fetch::probes(&staging, Some(&socket));
    results.push((
        "reads the directory it serves".into(),
        std::fs::read_dir(dir).is_ok(),
    ));
    results.push((
        "writes nothing in the directory it serves".into(),
        std::fs::write(dir.join(".velarx-probe"), "x").is_err(),
    ));
    drop(listener);
    let _ = rustix::fs::unlinkat(
        &*staging,
        velarx_sandbox::fetch::PROBE_SOCKET,
        rustix::fs::AtFlags::empty(),
    );
    println!("{}", serde_json::to_string(&results)?);
    Ok(())
}
