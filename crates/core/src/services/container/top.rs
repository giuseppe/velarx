// SPDX-License-Identifier: Apache-2.0
use super::*;

/// A process and all its descendants, by the `children` of their threads.
pub(super) fn process_tree(pid: u32) -> Vec<u32> {
    let mut out = vec![pid];
    let mut i = 0;
    while i < out.len() && out.len() < 65536 {
        let p = out[i];
        if let Ok(tasks) = std::fs::read_dir(format!("/proc/{p}/task")) {
            for t in tasks.flatten() {
                let children =
                    std::fs::read_to_string(t.path().join("children")).unwrap_or_default();
                out.extend(
                    children
                        .split_whitespace()
                        .filter_map(|c| c.parse::<u32>().ok()),
                );
            }
        }
        i += 1;
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// The pid of the host process `host` in its innermost PID namespace.
pub(super) fn pid_in_namespace(host: &str) -> Option<String> {
    let status = std::fs::read_to_string(format!("/proc/{host}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with("NSpid:"))?;
    line.split_whitespace().last().map(str::to_string)
}

/// The output of ps: the titles, and for each process as many fields, the
/// last one (the command) keeping its spaces.
pub(super) fn parse_ps(out: &str) -> TopResult {
    let mut lines = out.lines();
    let titles: Vec<String> = lines
        .next()
        .unwrap_or("")
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let n = titles.len().max(1);
    let processes = lines
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let mut fields = Vec::with_capacity(n);
            let mut rest = line.trim_start();
            while fields.len() + 1 < n {
                match rest.find(char::is_whitespace) {
                    Some(end) => {
                        fields.push(rest[..end].to_string());
                        rest = rest[end..].trim_start();
                    }
                    None => break,
                }
            }
            if !rest.is_empty() {
                fields.push(rest.trim_end().to_string());
            }
            fields
        })
        .collect();
    TopResult { titles, processes }
}

/// Process list result
/// podman's top descriptors (psgo): the name, the `ps -o` key, the title.
pub const TOP_DESCRIPTORS: &[(&str, &str, &str)] = &[
    ("args", "args", "COMMAND"),
    ("comm", "comm", "COMMAND"),
    ("etime", "etime", "ELAPSED"),
    ("group", "group", "GROUP"),
    ("hgroup", "egid", "HGROUP"),
    ("hpid", "pid", "HPID"),
    ("huser", "euid", "HUSER"),
    ("nice", "nice", "NI"),
    ("pcpu", "pcpu", "%CPU"),
    ("pgid", "pgid", "PGID"),
    ("pid", "pid", "PID"),
    ("ppid", "ppid", "PPID"),
    ("rgroup", "rgroup", "RGROUP"),
    ("ruser", "ruser", "RUSER"),
    ("time", "time", "TIME"),
    ("tty", "tty", "TTY"),
    ("user", "user", "USER"),
    ("vsz", "vsz", "VSZ"),
];

/// podman's top without descriptors.
pub const TOP_DEFAULT: &[&str] = &[
    "user", "pid", "ppid", "pcpu", "etime", "tty", "time", "args",
];

/// The descriptors of a `ps_args` that is a list of them (`args,pid`), or
/// none when it is `ps` options (`-ef`).
pub fn top_descriptor_list(ps_args: &str) -> Option<Vec<String>> {
    let a = ps_args.trim();
    if a.is_empty() {
        return Some(TOP_DEFAULT.iter().map(|s| s.to_string()).collect());
    }
    if a.starts_with('-') || a.contains(char::is_whitespace) {
        return None;
    }
    Some(a.split(',').map(str::to_string).collect())
}

/// What a process has run for: since it started, and its CPU time.
struct ProcessTimes {
    elapsed: std::time::Duration,
    cpu: std::time::Duration,
}

/// The times of the host process PID, from /proc/PID/stat (ticks of the
/// clock) and /proc/uptime.
fn process_times(pid: &str) -> Option<ProcessTimes> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // (the command, in parentheses, may hold spaces: the fields follow its
    // last parenthesis, the state being the first)
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    let tick = |i: usize| fields.get(i - 3)?.parse::<u64>().ok();
    let (utime, stime, start) = (tick(14)?, tick(15)?, tick(22)?);
    let hz = rustix::param::clock_ticks_per_second().max(1);
    let up: f64 = std::fs::read_to_string("/proc/uptime")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let ticks = |t: u64| std::time::Duration::from_nanos(t.saturating_mul(1_000_000_000 / hz));
    Some(ProcessTimes {
        elapsed: std::time::Duration::from_secs_f64(up).saturating_sub(ticks(start)),
        cpu: ticks(utime + stime),
    })
}

/// A duration as Go prints it, which is what psgo's ELAPSED and TIME
/// columns are.
fn go_duration(d: std::time::Duration) -> String {
    velarx_proto::duration::go_duration_string(i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
}

/// The id ID of the process, which the engine sees in its own user
/// namespace, as the host sees it: by the name FILE (the passwd or group
/// file of the container) gives that host id, else the number; an id the
/// namespace does not map is the overflow id.
fn host_id(id: &str, map: &str, overflow: &str, file: &str) -> String {
    let Ok(n) = id.parse::<u64>() else {
        return id.to_string();
    };
    let host = std::fs::read_to_string(map)
        .ok()
        .and_then(|m| mapped_id(&m, n))
        .map(|h| h.to_string())
        .unwrap_or_else(|| {
            std::fs::read_to_string(overflow)
                .map(|o| o.trim().to_string())
                .unwrap_or_else(|_| "65534".into())
        });
    let name = std::fs::read_to_string(file).ok().and_then(|f| {
        f.lines().find_map(|l| {
            let mut c = l.split(':');
            let name = c.next()?;
            (c.nth(1)? == host).then(|| name.to_string())
        })
    });
    name.unwrap_or(host)
}

/// ID of a user namespace as the namespace above it sees it, by a uid_map or
/// gid_map (`inside outside count` lines).
fn mapped_id(map: &str, id: u64) -> Option<u64> {
    map.lines().find_map(|l| {
        let mut f = l.split_whitespace().map(|w| w.parse::<u64>().ok());
        let (inside, outside, count) = (f.next()??, f.next()??, f.next()??);
        (id >= inside && id - inside < count).then(|| outside + (id - inside))
    })
}

impl ContainerService {
    /// The processes of a container with podman's top descriptors
    /// (`user,pid,args`): the pids are those of its PID namespace.
    pub async fn top_descriptors(
        &self,
        id: &str,
        descriptors: &[String],
    ) -> ContainerResult<TopResult> {
        let container = self.db.get_container(id).await?;
        let pids = Self::container_pids(&container)?;
        let keys: Vec<&(&str, &str, &str)> = descriptors
            .iter()
            .map(|d| {
                TOP_DESCRIPTORS
                    .iter()
                    .find(|(name, _, _)| name == d)
                    .ok_or_else(|| {
                        ContainerError::InvalidArgument(format!("unknown top descriptor `{d}`"))
                    })
            })
            .collect::<Result<_, _>>()?;
        let titles = keys.iter().map(|(_, _, t)| t.to_string()).collect();
        if pids.is_empty() {
            return Ok(TopResult {
                titles,
                processes: vec![],
            });
        }
        // ps: the host pid first, the ones that may hold spaces last
        let rest = keys
            .iter()
            .rposition(|(n, _, _)| matches!(*n, "args" | "comm"));
        let mut order: Vec<usize> = (0..keys.len()).filter(|i| Some(*i) != rest).collect();
        order.extend(rest);
        let mut fields = vec!["pid".to_string()];
        fields.extend(order.iter().map(|i| keys[*i].1.to_string()));
        let output = tokio::process::Command::new("ps")
            .arg("--no-headers")
            .args(["-o", &fields.join(",")])
            .args(["-p", &pids.join(",")])
            .output()
            .await
            .map_err(ContainerError::Io)?;
        let in_ns = pid_in_namespace;
        let mut processes = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let mut cols = Vec::with_capacity(fields.len());
            let mut rest_text = line.trim_start();
            while cols.len() + 1 < fields.len() {
                match rest_text.find(char::is_whitespace) {
                    Some(end) => {
                        cols.push(rest_text[..end].to_string());
                        rest_text = rest_text[end..].trim_start();
                    }
                    None => break,
                }
            }
            if !rest_text.is_empty() {
                cols.push(rest_text.trim_end().to_string());
            }
            if cols.len() != fields.len() {
                continue;
            }
            let mut row = vec![String::new(); keys.len()];
            for (k, i) in order.iter().enumerate() {
                let v = cols[k + 1].clone();
                row[*i] = match keys[*i].0 {
                    // the ids and the times as psgo shows them: the host's
                    // ids, named by the files of the container (psgo looks
                    // them up in its mount namespace), Go's durations
                    "huser" => host_id(
                        &v,
                        "/proc/self/uid_map",
                        "/proc/sys/fs/overflowuid",
                        &format!("/proc/{}/root/etc/passwd", cols[0]),
                    ),
                    "hgroup" => host_id(
                        &v,
                        "/proc/self/gid_map",
                        "/proc/sys/fs/overflowgid",
                        &format!("/proc/{}/root/etc/group", cols[0]),
                    ),
                    "etime" => process_times(&cols[0]).map_or(v, |t| go_duration(t.elapsed)),
                    "time" => process_times(&cols[0]).map_or(v, |t| go_duration(t.cpu)),
                    "pid" => in_ns(&cols[0]).unwrap_or(v),
                    "ppid" if pids.contains(&v) => in_ns(&v).unwrap_or(v),
                    "ppid" => "0".to_string(),
                    // (psgo's three decimals)
                    "pcpu" => v.parse::<f64>().map_or(v, |p| format!("{p:.3}")),
                    _ => v,
                };
            }
            processes.push(row);
        }
        Ok(TopResult { titles, processes })
    }

    /// The processes of its cgroup (exec sessions included), else, made in
    /// the cgroup of its monitor, those that descend from its process.  A
    /// container of `--cgroups=disabled` has none to list: podman's error.
    pub(super) fn container_pids(
        container: &velarx_db::ContainerRecord,
    ) -> ContainerResult<Vec<String>> {
        if !has_own_cgroup(container) {
            return Err(ContainerError::InvalidArgument(format!(
                "cannot run top on container {} as it did not create a cgroup: this container \
                 does not have a cgroup",
                container.id
            )));
        }
        let mut pids = Self::cgroup_pids(container)?;
        if pids.is_empty() {
            if let Some(pid) = container.pid.filter(|p| *p > 0) {
                pids = process_tree(pid as u32)
                    .iter()
                    .map(u32::to_string)
                    .collect();
            }
        }
        Ok(pids)
    }

    /// The processes of a container: podman's descriptors (`pid,args`, its
    /// default ones with none) or the arguments of `ps`.
    pub async fn top(&self, id: &str, ps_args: &[String]) -> ContainerResult<TopResult> {
        // podman's descriptors, one per argument or comma separated, when
        // it knows them all; else the arguments of ps (one argument is
        // split as a shell does, as podman's: a docker client sends one)
        let descriptors: Vec<String> = ps_args
            .iter()
            .flat_map(|a| a.split(','))
            .filter(|d| !d.is_empty())
            .map(str::to_string)
            .collect();
        if descriptors.is_empty() {
            let defaults: Vec<String> = TOP_DEFAULT.iter().map(|s| s.to_string()).collect();
            return self.top_descriptors(id, &defaults).await;
        }
        if descriptors
            .iter()
            .all(|d| TOP_DESCRIPTORS.iter().any(|(name, _, _)| name == d))
        {
            return self.top_descriptors(id, &descriptors).await;
        }
        let split;
        let ps_args = match ps_args {
            [one] => {
                split = velarx_wire::parse::split_quoted(one).map_err(|e| {
                    ContainerError::InvalidArgument(format!("parsing ps args: {e}"))
                })?;
                &split[..]
            }
            many => many,
        };
        let container = self.db.get_container(id).await?;

        let pids = Self::container_pids(&container)?;

        if pids.is_empty() {
            return Ok(TopResult {
                titles: ["UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"]
                    .map(str::to_string)
                    .to_vec(),
                processes: vec![],
            });
        }

        let output = tokio::process::Command::new("ps")
            .args(ps_args)
            .args(["-p", &pids.join(",")])
            .output()
            .await
            .map_err(ContainerError::Io)?;
        if !output.status.success() {
            // ps refuses options it does not know: the caller's error,
            // which podman reports as ps's
            return Err(ContainerError::Io(std::io::Error::other(format!(
                "ps({}): {}",
                ps_args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            ))));
        }
        let mut result = parse_ps(&String::from_utf8_lossy(&output.stdout));
        // the pids as the container sees them (podman's ps runs in its PID namespace)
        let column = |title: &str| result.titles.iter().position(|t| t == title);
        let (pid, ppid) = (column("PID"), column("PPID"));
        for row in &mut result.processes {
            if let Some(i) = ppid.filter(|i| *i < row.len()) {
                row[i] = if pids.contains(&row[i]) {
                    pid_in_namespace(&row[i]).unwrap_or_else(|| row[i].clone())
                } else {
                    "0".to_string()
                };
            }
            if let Some(i) = pid.filter(|i| *i < row.len()) {
                if let Some(p) = pid_in_namespace(&row[i]) {
                    row[i] = p;
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod top_tests {
    use super::*;

    #[test]
    fn ids_are_the_hosts() {
        let map = "         0       1002          1\n         1     100000      65536\n";
        assert_eq!(mapped_id(map, 0), Some(1002));
        assert_eq!(mapped_id(map, 5), Some(100004));
        assert_eq!(mapped_id(map, 70000), None);
        assert_eq!(
            mapped_id("0 0 4294967295", 1000),
            Some(1000),
            "the identity map of the initial namespace"
        );
    }

    #[test]
    fn the_command_keeps_its_spaces() {
        let t = parse_ps("UID PID CMD\nroot 1 sleep 25\nroot 7 top\n");
        assert_eq!(t.titles, ["UID", "PID", "CMD"]);
        assert_eq!(t.processes[0], ["root", "1", "sleep 25"]);
        assert_eq!(t.processes[1], ["root", "7", "top"]);
    }

    /// The processes of a container are those of the cgroup it was made
    /// in (its recorded path, or for a systemd one the scope its process is
    /// in) and of the cgroups below it; one made in the cgroup of its
    /// monitor has none (its tree is listed), and one with
    /// `--cgroups=disabled` is refused.
    #[test]
    fn the_recorded_cgroup_lists_the_processes() {
        let me = std::process::id();
        let rec = |cgroups: &str, cgroups_path: Option<String>| velarx_db::ContainerRecord {
            id: "c".into(),
            name: None,
            image_id: "i".into(),
            config: serde_json::to_string(&ContainerConfig {
                cgroups: cgroups.parse().unwrap(),
                cgroups_path,
                ..Default::default()
            })
            .unwrap(),
            state: RecordState::Running,
            pid: Some(me as i32),
            created_at: String::new(),
            started_at: None,
            finished_at: None,
            exit_code: None,
        };
        let own = velarx_base::cgroup::of_process(None).unwrap();
        let listed = |r| ContainerService::cgroup_pids(&r).unwrap();
        // (the cgroup of this process, from a cgroup above it: the
        // processes below are the container's too)
        let above = own
            .rsplit_once('/')
            .map(|(a, _)| a)
            .filter(|a| !a.is_empty());
        assert!(listed(rec("", Some(own.clone()))).contains(&me.to_string()));
        if let Some(above) = above {
            assert!(listed(rec("", Some(above.to_string()))).contains(&me.to_string()));
        }
        // a systemd path names the scope the process is in
        if let Some((prefix, name)) = own
            .rsplit('/')
            .next()
            .and_then(|u| u.strip_suffix(".scope"))
            .and_then(|u| u.split_once('-'))
        {
            let path = format!("x.slice:{prefix}:{name}");
            assert!(listed(rec("", Some(path))).contains(&me.to_string()));
            assert!(
                ContainerService::cgroup_pids(&rec("", Some("x.slice:no:such".into()))).is_err()
            );
        }
        assert!(listed(rec("", None)).is_empty());
        assert!(ContainerService::container_pids(&rec("", None))
            .unwrap()
            .contains(&me.to_string()));
        let refused = ContainerService::container_pids(&rec("disabled", None)).unwrap_err();
        assert!(refused.to_string().contains("did not create a cgroup"));
    }

    #[test]
    fn a_tree_has_its_root() {
        let me = std::process::id();
        assert!(process_tree(me).contains(&me));
    }
}
