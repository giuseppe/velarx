// SPDX-License-Identifier: Apache-2.0
//! The options of a build that come as text, from the command line of
//! `build` or from the parameters of the build routes of the API: one
//! reading of them for both.

use crate::request::{BuildRun, DeviceMapping, Ulimit};

/// The options of the RUN containers and of the final image, as given.
#[derive(Debug, Clone, Default)]
pub struct RunText {
    /// `--volume`, with absolute sources
    pub volumes: Vec<String>,
    pub add_hosts: Vec<String>,
    pub dns: Vec<String>,
    pub dns_search: Vec<String>,
    pub dns_options: Vec<String>,
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    pub security_opts: Vec<String>,
    /// `NAME=SOFT[:HARD]`
    pub ulimits: Vec<String>,
    pub devices: Vec<String>,
    /// In bytes
    pub shm_size: Option<u64>,
    /// `--env`: `KEY=VALUE`, or `KEY` for the value of the caller
    pub env: Vec<String>,
    pub unset_env: Vec<String>,
    pub unset_labels: Vec<String>,
    /// `--format`: `oci` (the Docker formats are refused)
    pub format: Option<String>,
    /// What the RUN containers take as it is (`--group-add`, the
    /// namespaces, the resources...).
    pub more: BuildRun,
}

/// The options read: for the RUN containers, `--env`.
pub struct RunParsed {
    pub run: BuildRun,
    pub env: Vec<(String, String)>,
}

impl RunText {
    /// Read the options; `lookup` gives the value of a variable `--env`
    /// names without one.
    pub fn parse(&self, lookup: impl Fn(&str) -> Option<String>) -> Result<RunParsed, String> {
        if let Some(f) = &self.format {
            velarx_base::docker::refuse_format_name(f)?;
            if f != "oci" {
                return Err(format!("unrecognized image type {f:?}"));
            }
        }
        let run = BuildRun {
            volumes: self.volumes.clone(),
            add_hosts: self.add_hosts.clone(),
            dns: self.dns.clone(),
            dns_search: self.dns_search.clone(),
            dns_options: self.dns_options.clone(),
            cap_add: self.cap_add.clone(),
            cap_drop: self.cap_drop.clone(),
            security_opts: self.security_opts.clone(),
            ulimits: self
                .ulimits
                .iter()
                .map(|u| Ulimit::parse(u))
                .collect::<Result<_, _>>()?,
            devices: self
                .devices
                .iter()
                .map(|d| DeviceMapping::parse(d))
                .collect(),
            shm_size: self.shm_size,
            ..self.more.clone()
        };
        let env = self
            .env
            .iter()
            .map(|e| match e.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (e.clone(), lookup(e).unwrap_or_default()),
            })
            .collect();
        Ok(RunParsed { run, env })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_text_options_fill_a_build() {
        let text = RunText {
            volumes: vec!["/a:/b".into()],
            ulimits: vec!["nofile=1:2".into()],
            devices: vec!["/dev/null:/dev/x:r".into()],
            shm_size: Some(1 << 20),
            env: vec!["A=1".into(), "B".into()],
            unset_env: vec!["C".into()],
            format: Some("oci".into()),
            ..Default::default()
        };
        let o = text.parse(|k| (k == "B").then(|| "2".to_string())).unwrap();
        assert_eq!(o.run.volumes, ["/a:/b"]);
        assert_eq!((o.run.ulimits[0].soft, o.run.ulimits[0].hard), (1, 2));
        assert_eq!(o.run.devices[0].cgroup_permissions, "r");
        assert_eq!(o.run.shm_size, Some(1 << 20));
        assert_eq!(o.env, [("A".into(), "1".into()), ("B".into(), "2".into())]);
        let bad = RunText {
            format: Some("zip".into()),
            ..Default::default()
        };
        assert!(bad.parse(|_| None).is_err());
        for f in ["docker", "v2s2"] {
            let docker = RunText {
                format: Some(f.into()),
                ..Default::default()
            };
            let e = docker.parse(|_| None).err().unwrap();
            assert!(e.contains("Docker image formats are not supported"), "{e}");
        }
    }
}
