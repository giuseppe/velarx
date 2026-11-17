// SPDX-License-Identifier: Apache-2.0
//! `velarx auto-update`: restart the systemd units of the containers whose
//! image changed (`io.containers.autoupdate=registry|local`).

use crate::client::{ClientError, EngineClient};
use clap::Args;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

pub const AUTOUPDATE_LABEL: &str = "io.containers.autoupdate";
pub const UNIT_LABEL: &str = "PODMAN_SYSTEMD_UNIT";

#[derive(Args, Clone)]
pub struct AutoUpdateArgs {
    /// Check for updates, restart nothing and pull nothing
    #[arg(long)]
    pub dry_run: bool,
    /// Go back to the previous image when the unit does not start with the new one
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub rollback: bool,
    /// Output format: json, or a template with {{.Unit}}, {{.Container}}, {{.Image}}, {{.Policy}}, {{.Updated}}
    #[arg(long)]
    pub format: Option<String>,
    /// Verify the TLS certificates of the registry (false also allows plain HTTP)
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub tls_verify: bool,
    /// The auth file of the registries, instead of the default ones
    #[arg(long)]
    pub authfile: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ctr {
    pub id: String,
    pub name: String,
    /// The image as the container was created with
    pub image: String,
    /// The id of the image the container runs
    pub image_id: String,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Row {
    pub unit: String,
    pub container: String,
    #[serde(rename = "ContainerName")]
    pub container_name: String,
    #[serde(rename = "ContainerID")]
    pub container_id: String,
    pub image: String,
    pub policy: String,
    /// true, false, pending (dry run), failed, rolled back
    pub updated: String,
    /// The image the container runs now, to go back to
    #[serde(skip)]
    old_image_id: String,
}

/// What the update needs from the system.
pub trait Updater {
    fn containers(&self) -> Result<Vec<Ctr>, String>;
    /// The id of the image `name` is now.
    fn image_id(&self, name: &str) -> Result<Option<String>, String>;
    /// Whether the registry has another version of the image than the store.
    fn remote_differs(&self, name: &str) -> Result<bool, String>;
    /// Pull `name`; the id of the image it is now.
    fn pull(&self, name: &str) -> Result<String, String>;
    fn tag(&self, image_id: &str, name: &str) -> Result<(), String>;
    /// Restart the unit and wait for the result.
    fn restart(&self, unit: &str) -> Result<(), String>;
}

#[derive(Debug, PartialEq)]
enum Policy {
    Registry,
    Local,
}

fn policy_of(c: &Ctr) -> Result<Option<Policy>, String> {
    match c.labels.get(AUTOUPDATE_LABEL).map(String::as_str) {
        None | Some("") | Some("disabled") => Ok(None),
        Some("registry") => Ok(Some(Policy::Registry)),
        Some("local") => Ok(Some(Policy::Local)),
        Some(p) => Err(format!(
            "container {}: invalid auto-update policy `{p}`",
            c.name
        )),
    }
}

fn same_image(a: &str, b: &str) -> bool {
    let a = velarx_shape::without_algorithm(a);
    let b = velarx_shape::without_algorithm(b);
    let n = a.len().min(b.len());
    n >= 12 && a[..n] == b[..n]
}

/// A systemd unit name as `systemctl` takes it: never an option.
fn valid_unit_name(unit: &str) -> bool {
    unit.len() <= 256
        && !unit.starts_with('-')
        && unit.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'.' | b'\\' | b'@' | b'-')
        })
}

pub fn update(
    backend: &dyn Updater,
    dry_run: bool,
    rollback: bool,
) -> Result<(Vec<Row>, Vec<String>), String> {
    let mut rows = Vec::new();
    let mut errors = Vec::new();
    // image name -> (the id after the pull, the pull failed)
    let mut pulled: HashMap<String, Result<Option<String>, String>> = HashMap::new();
    // unit -> indexes of the rows to restart
    let mut restarts: BTreeMap<String, Vec<usize>> = BTreeMap::new();

    for c in backend.containers()? {
        let policy = match policy_of(&c) {
            Ok(Some(p)) => p,
            Ok(None) => continue,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        let Some(unit) = c.labels.get(UNIT_LABEL).filter(|u| !u.is_empty()).cloned() else {
            errors.push(format!(
                "container {}: no {UNIT_LABEL} label: it is not run by a systemd unit",
                c.name
            ));
            continue;
        };
        if !valid_unit_name(&unit) {
            errors.push(format!(
                "container {}: the {UNIT_LABEL} label `{unit}` is not a unit name",
                c.name
            ));
            continue;
        }
        let policy_name = if policy == Policy::Registry {
            "registry"
        } else {
            "local"
        };
        let current = if policy == Policy::Registry && !dry_run {
            pulled
                .entry(c.image.clone())
                .or_insert_with(|| backend.pull(&c.image).map(Some))
                .clone()
        } else {
            backend.image_id(&c.image)
        };
        let mut row = Row {
            unit: unit.clone(),
            container: format!("{} ({})", &c.id[..c.id.len().min(12)], c.name),
            container_name: c.name.clone(),
            container_id: c.id.clone(),
            image: c.image.clone(),
            policy: policy_name.into(),
            updated: "false".into(),
            old_image_id: c.image_id.clone(),
        };
        let current = match current {
            Ok(Some(id)) => id,
            Ok(None) => {
                errors.push(format!("container {}: no image {}", c.name, c.image));
                row.updated = "failed".into();
                rows.push(row);
                continue;
            }
            Err(e) => {
                errors.push(format!("container {}: image {}: {e}", c.name, c.image));
                row.updated = "failed".into();
                rows.push(row);
                continue;
            }
        };
        let mut changed = !same_image(&c.image_id, &current);
        if dry_run && policy == Policy::Registry && !changed {
            match backend.remote_differs(&c.image) {
                Ok(d) => changed = d,
                Err(e) => {
                    errors.push(format!("container {}: image {}: {e}", c.name, c.image));
                    row.updated = "failed".into();
                    rows.push(row);
                    continue;
                }
            }
        }
        if changed {
            if dry_run {
                row.updated = "pending".into();
            } else {
                row.updated = "true".into();
                restarts.entry(unit).or_default().push(rows.len());
            }
        }
        rows.push(row);
    }

    for (unit, idx) in restarts {
        let Err(e) = backend.restart(&unit) else {
            continue;
        };
        errors.push(format!("restarting {unit}: {e}"));
        let mut rolled_back = rollback;
        if rollback {
            for &i in &idx {
                let (old, name) = (rows[i].old_image_id.clone(), rows[i].image.clone());
                if let Err(e) = backend.tag(&old, &name) {
                    errors.push(format!("rolling back {name}: {e}"));
                    rolled_back = false;
                }
            }
            if rolled_back {
                if let Err(e) = backend.restart(&unit) {
                    errors.push(format!("restarting {unit} after the rollback: {e}"));
                    rolled_back = false;
                }
            }
        }
        for &i in &idx {
            rows[i].updated = if rolled_back { "rolled back" } else { "failed" }.into();
        }
    }
    Ok((rows, errors))
}

fn render(template: &str, r: &Row) -> String {
    let mut out = String::new();
    let mut rest = template;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let Some(j) = rest[i..].find("}}") else { break };
        out.push_str(match rest[i + 2..i + j].trim().trim_start_matches('.') {
            "Unit" => &r.unit,
            "Container" => &r.container,
            "ContainerName" => &r.container_name,
            "ContainerID" => &r.container_id,
            "Image" => &r.image,
            "Policy" => &r.policy,
            "Updated" => &r.updated,
            _ => "",
        });
        rest = &rest[i + j + 2..];
    }
    out.push_str(rest);
    out.replace("\\t", "\t").replace("\\n", "\n")
}

pub fn print(rows: &[Row], format: Option<&str>) -> anyhow::Result<()> {
    match format {
        Some("json") => println!("{}", serde_json::to_string_pretty(rows)?),
        Some(t) => {
            for r in rows {
                println!("{}", render(t, r));
            }
        }
        None => {
            let w =
                |f: fn(&Row) -> usize, h: usize| rows.iter().map(f).max().unwrap_or(0).max(h) + 2;
            let (u, c, i) = (
                w(|r| r.unit.len(), 4),
                w(|r| r.container.len(), 9),
                w(|r| r.image.len(), 5),
            );
            println!(
                "{:<u$}{:<c$}{:<i$}{:<10}UPDATED",
                "UNIT", "CONTAINER", "IMAGE", "POLICY"
            );
            for r in rows {
                println!(
                    "{:<u$}{:<c$}{:<i$}{:<10}{}",
                    r.unit, r.container, r.image, r.policy, r.updated
                );
            }
        }
    }
    Ok(())
}

/// `repo:tag` of an image name (the tag is `latest` without one).
fn split_name(name: &str) -> (&str, &str) {
    match name.rsplit_once(':') {
        Some((repo, tag)) if !tag.contains('/') => (repo, tag),
        _ => (name, "latest"),
    }
}

/// The daemon and `systemctl`.
struct System<'a> {
    client: &'a EngineClient,
    tls_verify: bool,
    /// `--authfile`, the access of each registry from it.
    authfile: super::RegistryAccessArgs,
    access: &'a super::manifest::AccessFn<'a>,
}

impl Updater for System<'_> {
    fn containers(&self) -> Result<Vec<Ctr>, String> {
        let list = self
            .client
            .list_containers(true, &[format!("label={AUTOUPDATE_LABEL}")], false, false)
            .map_err(|e| e.to_string())?;
        Ok(list
            .into_iter()
            .map(|c| Ctr {
                // the image name the container was created with (the
                // listing shows the first name of the image, which can be
                // another tag of it)
                image: if c.image_ref.is_empty() {
                    c.image
                } else {
                    c.image_ref
                },
                id: c.id,
                name: c.name,
                image_id: c.image_id,
                labels: c.labels.into_iter().collect(),
            })
            .collect())
    }

    fn image_id(&self, name: &str) -> Result<Option<String>, String> {
        match self.client.inspect_image(name) {
            Ok(image) => Ok(Some(image.id).filter(|i| !i.is_empty())),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn remote_differs(&self, name: &str) -> Result<bool, String> {
        let access =
            (self.access)(self.client, &self.authfile, name, false).map_err(|e| e.to_string())?;
        let v = self
            .client
            .remote_digest(name, self.tls_verify, None, &access)
            .map_err(|e| e.to_string())?;
        Ok(v.local.as_deref() != Some(v.remote.as_str()))
    }

    fn pull(&self, name: &str) -> Result<String, String> {
        let access =
            (self.access)(self.client, &self.authfile, name, false).map_err(|e| e.to_string())?;
        self.client
            .pull_image(
                name,
                &crate::client::PullOptions {
                    tls_verify: self.tls_verify,
                    platform: None,
                    access: &access,
                    retry: Default::default(),
                    sources: None,
                },
            )
            .map_err(|e: ClientError| e.to_string())?;
        self.image_id(name)?
            .ok_or_else(|| format!("the image {name} is not there after the pull"))
    }

    fn tag(&self, image_id: &str, name: &str) -> Result<(), String> {
        let (repo, tag) = split_name(name);
        self.client
            .tag_image(image_id, &format!("{repo}:{tag}"))
            .map_err(|e| e.to_string())
    }
    fn restart(&self, unit: &str) -> Result<(), String> {
        let mut cmd = std::process::Command::new("systemctl");
        if !rustix::process::geteuid().is_root() {
            cmd.arg("--user");
        }
        let out = cmd
            .args(["restart", "--", unit])
            .output()
            .map_err(|e| format!("cannot run systemctl: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }
}

/// `access`: the credentials of the access flags for a reference.
pub fn run(
    args: AutoUpdateArgs,
    client: &EngineClient,
    access: &super::manifest::AccessFn,
) -> anyhow::Result<()> {
    let authfile = super::RegistryAccessArgs {
        authfile: args.authfile.clone(),
        ..Default::default()
    };
    // (an auth file that is not there is an error before anything is done)
    if args.authfile.is_some() {
        access(client, &authfile, "", false)?;
    }
    let system = System {
        client,
        tls_verify: args.tls_verify,
        authfile,
        access,
    };
    let (rows, errors) =
        update(&system, args.dry_run, args.rollback).map_err(anyhow::Error::msg)?;
    print(&rows, args.format.as_deref())?;
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("Error: {e}");
        }
        anyhow::bail!("{} error(s) while updating", errors.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Fake {
        ctrs: Vec<Ctr>,
        /// image name -> id
        images: RefCell<HashMap<String, String>>,
        /// name -> id the pull gives
        remote: HashMap<String, String>,
        failing_units: Vec<String>,
        log: RefCell<Vec<String>>,
    }

    impl Updater for Fake {
        fn containers(&self) -> Result<Vec<Ctr>, String> {
            Ok(self.ctrs.clone())
        }
        fn image_id(&self, name: &str) -> Result<Option<String>, String> {
            Ok(self.images.borrow().get(name).cloned())
        }
        fn remote_differs(&self, name: &str) -> Result<bool, String> {
            Ok(self.remote.get(name) != self.images.borrow().get(name))
        }
        fn pull(&self, name: &str) -> Result<String, String> {
            self.log.borrow_mut().push(format!("pull {name}"));
            let id = self.remote.get(name).ok_or("not found")?.clone();
            self.images.borrow_mut().insert(name.into(), id.clone());
            Ok(id)
        }
        fn tag(&self, id: &str, name: &str) -> Result<(), String> {
            self.log.borrow_mut().push(format!("tag {id} {name}"));
            self.images.borrow_mut().insert(name.into(), id.into());
            Ok(())
        }
        fn restart(&self, unit: &str) -> Result<(), String> {
            self.log.borrow_mut().push(format!("restart {unit}"));
            // a unit fails with the new image only
            let id = self
                .images
                .borrow()
                .values()
                .next()
                .cloned()
                .unwrap_or_default();
            if self.failing_units.contains(&unit.to_string()) && id.starts_with("new") {
                return Err("failed".into());
            }
            Ok(())
        }
    }

    fn ctr(name: &str, policy: &str, image_id: &str) -> Ctr {
        let mut labels = HashMap::new();
        labels.insert(AUTOUPDATE_LABEL.into(), policy.into());
        labels.insert(UNIT_LABEL.into(), format!("{name}.service"));
        Ctr {
            id: format!("{name}0123456789abcdef"),
            name: name.into(),
            image: "reg/app:1".into(),
            image_id: image_id.into(),
            labels,
        }
    }

    fn fake(ctrs: Vec<Ctr>, local: &str, remote: &str) -> Fake {
        let mut f = Fake {
            ctrs,
            ..Default::default()
        };
        f.images
            .borrow_mut()
            .insert("reg/app:1".into(), local.into());
        f.remote.insert("reg/app:1".into(), remote.into());
        f
    }

    const OLD: &str = "old000000000000";
    const NEW: &str = "new000000000000";

    #[test]
    fn registry_update_pulls_and_restarts() {
        let f = fake(vec![ctr("a", "registry", OLD)], OLD, NEW);
        let (rows, errors) = update(&f, false, true).unwrap();
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(rows[0].updated, "true");
        assert_eq!(*f.log.borrow(), ["pull reg/app:1", "restart a.service"]);
    }

    #[test]
    fn nothing_new_restarts_nothing() {
        let f = fake(vec![ctr("a", "registry", OLD)], OLD, OLD);
        let (rows, _) = update(&f, false, true).unwrap();
        assert_eq!(rows[0].updated, "false");
        assert_eq!(*f.log.borrow(), ["pull reg/app:1"]);
    }

    #[test]
    fn dry_run_changes_nothing() {
        let f = fake(
            vec![ctr("a", "registry", OLD), ctr("b", "local", OLD)],
            OLD,
            NEW,
        );
        let (rows, _) = update(&f, true, true).unwrap();
        assert_eq!(rows[0].updated, "pending");
        // the local policy looks at the store only
        assert_eq!(rows[1].updated, "false");
        assert!(f.log.borrow().is_empty());
    }

    #[test]
    fn local_policy_follows_the_store() {
        let f = fake(vec![ctr("a", "local", OLD)], NEW, NEW);
        let (rows, _) = update(&f, false, true).unwrap();
        assert_eq!(rows[0].updated, "true");
        assert_eq!(*f.log.borrow(), ["restart a.service"]);
    }

    #[test]
    fn one_pull_and_one_restart_per_image_and_unit() {
        let mut b = ctr("b", "registry", OLD);
        b.labels.insert(UNIT_LABEL.into(), "a.service".into());
        let f = fake(vec![ctr("a", "registry", OLD), b], OLD, NEW);
        update(&f, false, true).unwrap();
        assert_eq!(*f.log.borrow(), ["pull reg/app:1", "restart a.service"]);
    }

    #[test]
    fn failed_restart_rolls_back() {
        let mut f = fake(vec![ctr("a", "registry", OLD)], OLD, NEW);
        f.failing_units = vec!["a.service".into()];
        let (rows, errors) = update(&f, false, true).unwrap();
        assert_eq!(rows[0].updated, "rolled back");
        assert_eq!(errors.len(), 1);
        assert_eq!(
            *f.log.borrow(),
            [
                "pull reg/app:1",
                "restart a.service",
                &format!("tag {OLD} reg/app:1"),
                "restart a.service"
            ]
        );
        assert_eq!(f.images.borrow()["reg/app:1"], OLD);
    }

    #[test]
    fn failed_restart_without_rollback() {
        let mut f = fake(vec![ctr("a", "registry", OLD)], OLD, NEW);
        f.failing_units = vec!["a.service".into()];
        let (rows, _) = update(&f, false, false).unwrap();
        assert_eq!(rows[0].updated, "failed");
        assert_eq!(f.images.borrow()["reg/app:1"], NEW);
    }

    #[test]
    fn bad_labels_are_errors_not_updates() {
        let mut no_unit = ctr("a", "registry", OLD);
        no_unit.labels.remove(UNIT_LABEL);
        let bad = ctr("b", "sometimes", OLD);
        let off = ctr("c", "disabled", OLD);
        let f = fake(vec![no_unit, bad, off], OLD, NEW);
        let (rows, errors) = update(&f, false, true).unwrap();
        assert!(rows.is_empty());
        assert_eq!(errors.len(), 2);
        assert!(errors[1].contains("invalid auto-update policy"));
        assert!(f.log.borrow().is_empty());
    }

    #[test]
    fn a_unit_label_that_is_an_option_is_an_error() {
        for bad in ["--host=evil", "-H", "a b.service", "a\nb"] {
            let mut c = ctr("a", "registry", OLD);
            c.labels.insert(UNIT_LABEL.into(), bad.into());
            let f = fake(vec![c], OLD, NEW);
            let (rows, errors) = update(&f, false, true).unwrap();
            assert!(rows.is_empty(), "{bad}");
            assert_eq!(errors.len(), 1, "{bad}");
            assert!(f.log.borrow().is_empty(), "{bad}");
        }
        assert!(valid_unit_name("app@1.service"));
        assert!(valid_unit_name("container-a\\x2db.service"));
    }

    #[test]
    fn image_names() {
        assert_eq!(
            split_name("localhost:5000/app:1"),
            ("localhost:5000/app", "1")
        );
        assert_eq!(
            split_name("localhost:5000/app"),
            ("localhost:5000/app", "latest")
        );
        assert_eq!(split_name("app"), ("app", "latest"));
    }

    #[test]
    fn templates_and_json() {
        let f = fake(vec![ctr("a", "local", OLD)], OLD, OLD);
        let (rows, _) = update(&f, true, true).unwrap();
        assert_eq!(
            render("{{.Unit}} {{.Updated}}", &rows[0]),
            "a.service false"
        );
        let j = serde_json::to_value(&rows).unwrap();
        assert_eq!(j[0]["Unit"], "a.service");
        assert_eq!(j[0]["ContainerName"], "a");
    }
}
