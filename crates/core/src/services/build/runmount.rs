// SPDX-License-Identifier: Apache-2.0
//! The options of `RUN --mount=`, as buildah and BuildKit take them:
//! `type=bind|cache|tmpfs|secret|ssh` and the options of each.

use serde::Serialize;

/// The kind of a mount of a RUN step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Bind,
    Cache,
    Tmpfs,
    Secret,
    Ssh,
}

/// How the steps that use one cache directory at the same time share it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Sharing {
    /// All of them at once
    #[default]
    Shared,
    /// One at a time: the others wait
    Locked,
    /// One of them: the others get an empty directory of their own
    Private,
}

/// One `--mount=` of a RUN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunMount {
    pub kind: Kind,
    /// Absolute, clean.
    pub target: String,
    /// The target was given (a secret with `env` and no target is not a
    /// file).
    #[serde(skip)]
    pub target_given: bool,
    /// The path in the root of `from` (the context by default), clean,
    /// relative; empty for the root.
    pub source: String,
    /// A stage, a named context or an image.
    pub from: Option<String>,
    /// bind: writes allowed (and discarded); cache: false with `ro`.
    pub rw: bool,
    /// cache: the directory's name (the target by default); secret, ssh:
    /// which one.
    pub id: Option<String>,
    pub sharing: Sharing,
    /// The mode of a new cache directory, of a secret file, of an agent
    /// socket.
    pub mode: Option<u32>,
    pub uid: u32,
    pub gid: u32,
    /// tmpfs: `size=` (bytes, or with a unit as mount(8) takes it).
    pub size: Option<String>,
    /// tmpfs: `tmpfs-mode=`.
    pub tmpfs_mode: Option<u32>,
    /// secret, ssh: a missing one fails the step (else the mount is left
    /// out).
    pub required: bool,
    /// secret: the variable the value is given in.
    pub env: Option<String>,
    /// Options of the OCI mount kept as given: `nosuid`, `nodev`,
    /// `noexec`, the propagation, `bind` for `bind-nonrecursive`.
    pub options: Vec<String>,
    /// `z`, `Z` or `relabel=shared|private`.
    pub relabel: Option<String>,
}

fn clean_target(t: &str, workdir: &str) -> Result<String, String> {
    let joined = if t.starts_with('/') {
        t.to_string()
    } else {
        format!("{}/{t}", if workdir.is_empty() { "/" } else { workdir })
    };
    let clean = velarx_wire::cp::clean_path(&joined);
    if clean == "/" {
        return Err("the target of a mount cannot be /".into());
    }
    Ok(clean)
}

/// A path inside the root of a mount source: `..` stays in it.
fn clean_source(s: &str) -> String {
    velarx_wire::cp::clean_path(&format!("/{s}"))
        .trim_start_matches('/')
        .to_string()
}

fn octal(name: &str, v: &str) -> Result<u32, String> {
    u32::from_str_radix(v, 8)
        .ok()
        .filter(|m| *m <= 0o7777)
        .ok_or_else(|| format!("invalid {name} `{v}`: an octal mode"))
}

fn number(name: &str, v: &str) -> Result<u32, String> {
    v.parse()
        .map_err(|_| format!("invalid {name} `{v}`: a number"))
}

fn boolean(name: &str, v: Option<&str>) -> Result<bool, String> {
    match v.map(str::to_ascii_lowercase).as_deref() {
        None | Some("" | "true" | "1" | "t") => Ok(true),
        Some("false" | "0" | "f") => Ok(false),
        Some(o) => Err(format!("invalid {name} `{o}`: true or false")),
    }
}

impl RunMount {
    /// Read the value of a `--mount=` (its variables expanded); `workdir`
    /// is the directory of a relative target, `ssh_index` the number of
    /// the ssh mounts before this one (the default target of an agent).
    pub fn parse(spec: &str, workdir: &str, ssh_index: usize) -> Result<Self, String> {
        let bad = |e: String| format!("--mount={spec}: {e}");
        let mut kind = Kind::Bind;
        let fields: Vec<(&str, Option<&str>)> = spec
            .split(',')
            .filter(|f| !f.is_empty())
            .map(|f| match f.split_once('=') {
                Some((k, v)) => (k.trim(), Some(v)),
                None => (f.trim(), None),
            })
            .collect();
        for (k, v) in &fields {
            if *k == "type" {
                kind = match v.unwrap_or("") {
                    "bind" => Kind::Bind,
                    "cache" => Kind::Cache,
                    "tmpfs" => Kind::Tmpfs,
                    "secret" => Kind::Secret,
                    "ssh" => Kind::Ssh,
                    t => {
                        return Err(bad(format!(
                            "unknown mount type `{t}`: bind, cache, tmpfs, secret or ssh"
                        )))
                    }
                };
            }
        }
        let mut m = RunMount {
            kind,
            target: String::new(),
            target_given: false,
            source: String::new(),
            from: None,
            rw: kind == Kind::Cache,
            id: None,
            sharing: Sharing::Shared,
            mode: None,
            uid: 0,
            gid: 0,
            size: None,
            tmpfs_mode: None,
            required: false,
            env: None,
            options: Vec::new(),
            relabel: None,
        };
        for (k, v) in fields {
            let value = || {
                v.filter(|v| !v.is_empty())
                    .ok_or_else(|| bad(format!("`{k}` needs a value")))
            };
            let flag = || {
                if v.is_some() {
                    Err(bad(format!("`{k}` takes no value")))
                } else {
                    Ok(())
                }
            };
            let path_like = matches!(m.kind, Kind::Bind | Kind::Cache);
            match (k, m.kind) {
                ("type", _) => {}
                ("target" | "dst" | "destination", _) => {
                    m.target = clean_target(value()?, workdir).map_err(bad)?;
                    m.target_given = true;
                }
                ("source" | "src", _) if path_like => m.source = clean_source(value()?),
                ("from", _) if path_like => m.from = Some(value()?.to_string()),
                ("rw" | "readwrite", Kind::Bind | Kind::Cache) => {
                    m.rw = boolean(k, v).map_err(bad)?
                }
                ("ro" | "readonly", Kind::Bind | Kind::Cache | Kind::Tmpfs) => {
                    m.rw = !boolean(k, v).map_err(bad)?;
                    if m.kind == Kind::Tmpfs && !m.rw {
                        m.options.push("ro".into());
                    }
                }
                ("nosuid" | "nodev" | "noexec", Kind::Bind | Kind::Cache | Kind::Tmpfs) => {
                    flag()?;
                    m.options.push(k.to_string());
                }
                ("bind-nonrecursive", Kind::Bind) => {
                    flag()?;
                    m.options.push("bind".into());
                }
                (
                    "shared" | "rshared" | "private" | "rprivate" | "slave" | "rslave",
                    Kind::Bind | Kind::Cache,
                ) => {
                    flag()?;
                    m.options.push(k.to_string());
                }
                ("bind-propagation", Kind::Bind | Kind::Cache) => {
                    let p = value()?;
                    if !matches!(
                        p,
                        "shared" | "rshared" | "private" | "rprivate" | "slave" | "rslave"
                    ) {
                        return Err(bad(format!("invalid bind-propagation `{p}`")));
                    }
                    m.options.push(p.to_string());
                }
                ("z" | "Z", Kind::Bind | Kind::Cache) => {
                    flag()?;
                    m.relabel = Some(k.to_string());
                }
                ("relabel", Kind::Bind) => {
                    m.relabel = Some(
                        match value()? {
                            "shared" => "z",
                            "private" => "Z",
                            r => {
                                return Err(bad(format!(
                                    "invalid relabel `{r}`: shared or private"
                                )))
                            }
                        }
                        .to_string(),
                    )
                }
                // (an option of macOS: Linux has no such thing to change)
                ("consistency", Kind::Bind) => {
                    let c = value()?;
                    if !matches!(c, "consistent" | "cached" | "delegated") {
                        return Err(bad(format!("invalid consistency `{c}`")));
                    }
                }
                ("id", Kind::Cache | Kind::Secret | Kind::Ssh) => m.id = Some(value()?.to_string()),
                ("sharing", Kind::Cache) => {
                    m.sharing = match value()? {
                        "shared" => Sharing::Shared,
                        "locked" => Sharing::Locked,
                        "private" => Sharing::Private,
                        s => {
                            return Err(bad(format!(
                                "invalid sharing `{s}`: shared, locked or private"
                            )))
                        }
                    }
                }
                ("mode", Kind::Cache | Kind::Secret | Kind::Ssh) => {
                    m.mode = Some(octal(k, value()?).map_err(bad)?)
                }
                ("uid", Kind::Cache | Kind::Secret | Kind::Ssh) => {
                    m.uid = number(k, value()?).map_err(bad)?
                }
                ("gid", Kind::Cache | Kind::Secret | Kind::Ssh) => {
                    m.gid = number(k, value()?).map_err(bad)?
                }
                ("size" | "tmpfs-size", Kind::Tmpfs) => {
                    let s = value()?;
                    let digits = s.trim_end_matches(['k', 'm', 'g', 'K', 'M', 'G', '%']);
                    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
                        return Err(bad(format!("invalid size `{s}`")));
                    }
                    m.size = Some(s.to_string());
                }
                ("tmpfs-mode", Kind::Tmpfs) => {
                    m.tmpfs_mode = Some(octal(k, value()?).map_err(bad)?)
                }
                ("required", Kind::Secret | Kind::Ssh) => {
                    m.required = boolean(k, v).map_err(bad)?
                }
                ("env", Kind::Secret) => {
                    let e = value()?;
                    if !e.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                        return Err(bad(format!("invalid variable name `{e}`")));
                    }
                    m.env = Some(e.to_string());
                }
                _ => {
                    return Err(bad(format!(
                        "`{k}` is not an option of a {} mount",
                        serde_json::to_value(m.kind)
                            .ok()
                            .and_then(|v| v.as_str().map(str::to_string))
                            .unwrap_or_default()
                    )))
                }
            }
        }
        match m.kind {
            Kind::Secret => {
                if m.id.is_none() && m.target_given {
                    m.id = m.target.rsplit('/').next().map(str::to_string);
                }
                let id =
                    m.id.clone()
                        .ok_or_else(|| bad("a secret mount needs an id or a target".into()))?;
                if !m.target_given {
                    m.target = clean_target(&format!("/run/secrets/{id}"), "/").map_err(bad)?;
                }
            }
            Kind::Ssh => {
                m.id.get_or_insert_with(|| "default".into());
                if !m.target_given {
                    m.target = format!("/run/buildkit/ssh_agent.{ssh_index}");
                }
            }
            _ if !m.target_given => return Err(bad("a mount needs a target".into())),
            _ => {}
        }
        Ok(m)
    }

    /// The name of the cache directory: the id (else the target) and the
    /// owner, hashed, as buildah names them (no path of the user's in it).
    pub fn cache_name(&self) -> String {
        let key = format!(
            "{}:{}:{}",
            self.id.as_deref().unwrap_or(&self.target),
            self.uid,
            self.gid
        );
        velarx_types::digest::Digest::of(velarx_types::digest::Algorithm::Sha256, key.as_bytes())
            .hex()[..16]
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<RunMount, String> {
        RunMount::parse(s, "/work", 0)
    }

    #[test]
    fn the_options_of_each_mount_type() {
        let m = p("type=bind,source=../x/./y,target=sub,from=builder,rw").unwrap();
        assert_eq!(
            (
                m.kind,
                m.source.as_str(),
                m.target.as_str(),
                m.from.as_deref(),
                m.rw
            ),
            (Kind::Bind, "x/y", "/work/sub", Some("builder"), true)
        );
        let m = p("target=/src").unwrap();
        assert_eq!((m.kind, m.rw, m.source.as_str()), (Kind::Bind, false, ""));
        let m =
            p("type=cache,target=/root/.cache,id=go,sharing=locked,mode=0700,uid=1000,gid=2,ro")
                .unwrap();
        assert_eq!(
            (m.sharing, m.mode, m.uid, m.gid, m.rw, m.id.as_deref()),
            (Sharing::Locked, Some(0o700), 1000, 2, false, Some("go"))
        );
        assert!(p("type=cache,target=/c").unwrap().rw);
        let m = p("type=tmpfs,target=/t,size=64m,tmpfs-mode=1777,noexec").unwrap();
        assert_eq!(
            (m.size.as_deref(), m.tmpfs_mode),
            (Some("64m"), Some(0o1777))
        );
        assert_eq!(m.options, ["noexec"]);
        let m = p("type=secret,id=tok").unwrap();
        assert_eq!(
            (m.target.as_str(), m.target_given, m.required),
            ("/run/secrets/tok", false, false)
        );
        let m = p("type=secret,target=/etc/key,required,mode=0440,uid=5").unwrap();
        assert_eq!(
            (m.id.as_deref(), m.mode, m.uid, m.required),
            (Some("key"), Some(0o440), 5, true)
        );
        let m = p("type=secret,id=tok,env=TOKEN,required=false").unwrap();
        assert_eq!(m.env.as_deref(), Some("TOKEN"));
        let m = RunMount::parse("type=ssh", "/", 2).unwrap();
        assert_eq!(
            (m.id.as_deref(), m.target.as_str()),
            (Some("default"), "/run/buildkit/ssh_agent.2")
        );

        for bad in [
            "type=nfs,target=/x",
            "type=bind",
            "type=bind,target=/",
            "type=bind,target=/x,size=1",
            "type=tmpfs,target=/x,from=a",
            "type=cache,target=/x,sharing=sometimes",
            "type=cache,target=/x,mode=999",
            "type=cache,target=/x,uid=root",
            "type=secret",
            "type=secret,id=a,env=A-B",
            "type=secret,id=a,source=x",
            "type=bind,target=/x,nosuid=1",
            "type=bind,target=/x,rw=maybe",
            "type=tmpfs,target=/x,size=lots",
            "type=bind,target=/x,id=a",
        ] {
            assert!(p(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn cache_directories_are_named_by_id_or_target_and_owner() {
        let a = p("type=cache,target=/a,id=x").unwrap().cache_name();
        assert_eq!(a, p("type=cache,target=/b,id=x").unwrap().cache_name());
        assert_ne!(
            a,
            p("type=cache,target=/a,id=x,uid=1").unwrap().cache_name()
        );
        assert_ne!(a, p("type=cache,target=/a").unwrap().cache_name());
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
