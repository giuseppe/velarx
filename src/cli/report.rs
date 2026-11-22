// SPDX-License-Identifier: Apache-2.0
//! What podman's list and inspect commands print: `--format`
//! templates, `--quiet`, `--noheading`, `--no-trunc`, `--filter`, on the
//! JSON of the libpod API (the server's, or the engine's of the command)
//! with the fields of podman's command line.

use super::template;
use crate::client::{EngineClient, Kind};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use velarx_proto::engine::Condition;

/// The output options of a podman list command.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct ListOutput {
    /// Print only the IDs (the names of volumes and networks)
    #[arg(long, short)]
    pub quiet: bool,
    /// Print no header row
    #[arg(long, short = 'n')]
    pub noheading: bool,
    /// Do not truncate the IDs
    #[arg(long)]
    pub no_trunc: bool,
    /// Go template of each item, `json`, or `table ...`
    #[arg(long, allow_hyphen_values = true)]
    pub format: Option<String>,
    /// KEY=VALUE filters
    #[arg(long, short)]
    pub filter: Vec<String>,
}

/// What `images` takes besides the output options.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct ImagesArgs {
    /// Show the digests
    #[arg(long)]
    pub digests: bool,
    /// Show the names each image had
    #[arg(long)]
    pub history: bool,
    /// List the pulls in progress too, with a LAZY column
    #[arg(long)]
    pub lazy: bool,
    /// Sort by created, id, repository, size or tag
    #[arg(long, value_name = "FIELD")]
    pub sort: Option<String>,
    /// Only the images of this name
    pub image: Option<String>,
}

/// The output options of `ps`: those of the other lists, but -n, which is
/// --last there.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct PsOutput {
    /// Print only the IDs
    #[arg(long, short)]
    pub quiet: bool,
    /// Print no header row
    #[arg(long)]
    pub noheading: bool,
    /// Do not truncate the IDs
    #[arg(long)]
    pub no_trunc: bool,
    /// Go template of each container, `json`, or `table ...`
    #[arg(long, allow_hyphen_values = true)]
    pub format: Option<String>,
    /// KEY=VALUE filters
    #[arg(long, short)]
    pub filter: Vec<String>,
}

impl From<PsOutput> for ListOutput {
    fn from(o: PsOutput) -> Self {
        ListOutput {
            quiet: o.quiet,
            noheading: o.noheading,
            no_trunc: o.no_trunc,
            format: o.format,
            filter: o.filter,
        }
    }
}

/// The options of `ps` that other lists have not.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct PsArgs {
    /// The N containers made last (all states; 0 or less: no limit)
    #[arg(long, short = 'n')]
    pub last: Option<i64>,
    /// The container made last (all states): --last 1
    #[arg(long, short = 'l', conflicts_with = "last")]
    pub latest: bool,
    /// Sort by command, created, id, image, names, runningfor, status
    #[arg(long)]
    pub sort: Option<String>,
    /// Show the pod of each container
    #[arg(long, short = 'p')]
    pub pod: bool,
    /// Also the containers of other tools in the storage (the store has
    /// none: the list is the same)
    #[arg(long)]
    pub external: bool,
    /// The size of the writable layer of each container, and the virtual size
    #[arg(long, short = 's')]
    pub size: bool,
    /// The namespaces of the containers
    #[arg(long = "namespace", alias = "ns")]
    pub ns: bool,
    /// Sync the state with the runtime (it is always read from it)
    #[arg(long)]
    pub sync: bool,
    /// List again every N seconds
    #[arg(long, short = 'w', value_name = "SECONDS")]
    pub watch: Option<u64>,
}

/// podman's `Status` of a container in `ps`: "Up 3 minutes", "Exited (0)
/// 2 hours ago", "Created"; with the health of a container that has a
/// check, `c["Status"]` of the list, after: "Up 3 minutes (healthy)".
pub fn ps_status(c: &Value) -> String {
    let mut text = ps_state_text(c);
    if let Some(health) = c["Status"].as_str().filter(|h| !h.is_empty()) {
        text = format!("{text} ({health})");
    }
    text
}

fn ps_state_text(c: &Value) -> String {
    let since = |k: &str| c[k].as_i64().filter(|t| *t > 0);
    match c["State"].as_str().unwrap_or_default() {
        "running" => match since("StartedAt") {
            Some(t) => format!("Up {}", human_since(t).trim_end_matches(" ago")),
            None => "Up".into(),
        },
        "paused" => "Paused".into(),
        "exited" | "stopped" => {
            let code = c["ExitCode"].as_i64().unwrap_or(0);
            match since("ExitedAt") {
                Some(t) => format!("Exited ({code}) {}", human_since(t)),
                None => format!("Exited ({code})"),
            }
        }
        "created" | "configured" | "initialized" => "Created".into(),
        other => {
            let mut c = other.chars();
            c.next()
                .map(|f| f.to_uppercase().chain(c).collect())
                .unwrap_or_default()
        }
    }
}

fn short(id: &str, no_trunc: bool) -> String {
    let id = velarx_shape::without_algorithm(id);
    if no_trunc {
        id.to_string()
    } else {
        id.chars().take(12).collect()
    }
}

/// The id of an image in a list: 12 digits, or with `--no-trunc` as podman
/// shows it, `sha256:` and the 64 digits (the digest of the manifest for an
/// image whose id has 12, from before ids were whole).
fn image_id(id: &str, digest: &Value, no_trunc: bool) -> String {
    let id = velarx_shape::without_algorithm(id);
    if !no_trunc {
        return id.chars().take(12).collect();
    }
    let whole = digest
        .as_str()
        .map(velarx_shape::without_algorithm)
        .filter(|d| (d.len() == 64 || d.len() == 128) && d.starts_with(id));
    velarx_shape::id_with_algorithm(if id.len() == 64 || id.len() == 128 {
        id
    } else {
        whole.unwrap_or(id)
    })
}

/// A time of the API, in nanoseconds since the epoch: an RFC 3339 string
/// (podman's time.Time) or seconds.
pub fn created_ns(v: &Value) -> i64 {
    match v {
        Value::String(t) => chrono::DateTime::parse_from_rfc3339(t)
            .ok()
            .and_then(|t| t.timestamp_nanos_opt())
            .unwrap_or(0),
        v => v.as_i64().unwrap_or(0).saturating_mul(1_000_000_000),
    }
}

/// How long ago, as podman says it (go-units' HumanDuration).
pub fn human_since(unix: i64) -> String {
    let s = (chrono::Utc::now().timestamp() - unix).max(0);
    format!("{} ago", velarx_shape::units::human_duration(s))
}

/// A size as podman prints it (3 significant digits, decimal units).
pub fn human_size(n: f64) -> String {
    let units = ["B", "kB", "MB", "GB", "TB", "PB"];
    let mut v = n.max(0.0);
    let mut i = 0;
    while v >= 1000.0 && i + 1 < units.len() {
        v /= 1000.0;
        i += 1;
    }
    let digits = if v >= 100.0 {
        0
    } else if v >= 10.0 {
        1
    } else {
        2
    };
    let s = format!("{v:.digits$}");
    let s = if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    };
    format!("{s} {}", units[i])
}

pub use velarx_shape::units::{go_bytes_size, go_size, go_size_with};

/// One reading of `stats` as podman's templates see it (its
/// `containerStats`): `avg_cpu` is the average of the CPU percentages of
/// the readings so far.
pub fn stats_fields(
    s: &velarx_proto::workload::StatsRecord,
    avg_cpu: f64,
    no_trunc: bool,
) -> Value {
    // (the engine's limit is the memory of the host when it has none)
    let limit = match s.mem_limit {
        0 => {
            let si = rustix::system::sysinfo();
            (si.totalram as u64).saturating_mul(u64::from(si.mem_unit))
        }
        l => l,
    };
    let mem_perc = if limit > 0 {
        s.mem_usage as f64 / limit as f64 * 100.0
    } else {
        0.0
    };
    let pair = |a: u64, b: u64, f: fn(f64) -> String| format!("{} / {}", f(a as f64), f(b as f64));
    let rx: u64 = s.networks.iter().map(|n| n.rx_bytes).sum();
    let tx: u64 = s.networks.iter().map(|n| n.tx_bytes).sum();
    let network: Map<String, Value> = s
        .networks
        .iter()
        .map(|n| {
            (
                n.name.clone(),
                json!({
                    "RxBytes": n.rx_bytes, "RxDropped": n.rx_dropped,
                    "RxErrors": n.rx_errors, "RxPackets": n.rx_packets,
                    "TxBytes": n.tx_bytes, "TxDropped": n.tx_dropped,
                    "TxErrors": n.tx_errors, "TxPackets": n.tx_packets,
                }),
            )
        })
        .collect();
    let cpu_ns = i64::try_from(s.cpu_nano).unwrap_or(i64::MAX);
    // (the reading itself, which podman's embeds)
    let embedded = json!({
        "AvgCPU": avg_cpu,
        "ContainerID": s.id,
        "Name": s.name,
        "PerCPU": [],
        "CPU": s.cpu_percent,
        "CPUNano": s.cpu_nano,
        "CPUSystemNano": s.cpu_system_nano,
        "SystemNano": s.time_ns,
        "MemUsage": s.mem_usage,
        "MemLimit": limit,
        "MemPerc": mem_perc,
        "Network": network.clone(),
        "BlockInput": s.block_read,
        "BlockOutput": s.block_write,
        "PIDs": s.pids,
        "UpTime": template::go_duration_value(cpu_ns),
        "Duration": s.cpu_nano,
    });
    json!({
        "ContainerStats": embedded,
        "ContainerID": s.id,
        "ID": short(&s.id, no_trunc),
        "Name": s.name,
        "CPU": s.cpu_percent,
        "CPUPerc": format!("{:.2}%", s.cpu_percent),
        "AvgCPU": avg_cpu,
        "AVGCPU": format!("{avg_cpu:.2}%"),
        "CPUNano": s.cpu_nano,
        "CPUSystemNano": s.cpu_system_nano,
        "SystemNano": s.time_ns,
        "PerCPU": [],
        "MemUsage": pair(s.mem_usage, limit, go_size),
        "MemUsageBytes": pair(s.mem_usage, limit, go_bytes_size),
        "MemLimit": limit,
        "MemPerc": format!("{mem_perc:.2}%"),
        "Network": network,
        "NetIO": pair(rx, tx, go_size),
        "BlockInput": s.block_read,
        "BlockOutput": s.block_write,
        "BlockIO": pair(s.block_read, s.block_write, go_size),
        "PIDs": s.pids,
        "PIDS": s.pids.to_string(),
        // (the CPU time, as podman's)
        "UpTime": template::go_duration_value(cpu_ns),
        "Up": velarx_proto::duration::go_duration_string(cpu_ns),
        "Duration": s.cpu_nano,
    })
}

/// `stats --format json`: podman's list of the readings as text.
pub fn stats_json(items: &[Value]) -> anyhow::Result<String> {
    let rows: Vec<Value> = items
        .iter()
        .map(|i| {
            json!({
                "id": i["ID"], "name": i["Name"], "cpu_time": i["Up"],
                "cpu_percent": i["CPUPerc"], "avg_cpu": i["AVGCPU"],
                "mem_usage": i["MemUsage"], "mem_percent": i["MemPerc"],
                "net_io": i["NetIO"], "block_io": i["BlockIO"], "pids": i["PIDS"],
            })
        })
        .collect();
    // (Go's MarshalIndent with one space)
    let mut out = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(
        &mut out,
        serde_json::ser::PrettyFormatter::with_indent(b" "),
    );
    serde::Serialize::serialize(&rows, &mut ser)?;
    Ok(String::from_utf8(out)?)
}

/// The rows of podman's `system df` from libpod's report: Images,
/// Containers, Local Volumes, with its fields (`Type`, `Total`, `Active`,
/// `RawSize`, `RawReclaimable`, `Size`, `Reclaimable`).
pub fn df_summary(report: &Value) -> Vec<Value> {
    let list = |k: &str| report[k].as_array().cloned().unwrap_or_default();
    let int = |v: &Value, k: &str| v[k].as_i64().unwrap_or(0);
    let mut seen = std::collections::HashSet::new();
    let (mut active, mut used) = (0, 0);
    let images = list("Images");
    for i in &images {
        if !seen.insert(i["ImageID"].as_str().unwrap_or_default().to_string()) {
            continue;
        }
        if int(i, "Containers") > 0 {
            active += 1;
            used += int(i, "UniqueSize");
        }
    }
    let images_size = int(report, "ImagesSize");
    let containers = list("Containers");
    let (mut con_active, mut con_size, mut con_reclaimable) = (0, 0, 0);
    for c in &containers {
        if c["Status"] == "running" {
            con_active += 1;
        } else {
            con_reclaimable += int(c, "RWSize");
        }
        con_size += int(c, "RWSize");
    }
    let volumes = list("Volumes");
    let (mut vol_active, mut vol_size, mut vol_reclaimable) = (0, 0, 0);
    for v in &volumes {
        vol_active += int(v, "Links");
        vol_size += int(v, "Size");
        vol_reclaimable += int(v, "ReclaimableSize");
    }
    [
        (
            "Images",
            images.len() as i64,
            active,
            images_size,
            images_size - used,
        ),
        (
            "Containers",
            containers.len() as i64,
            con_active,
            con_size,
            con_reclaimable,
        ),
        (
            "Local Volumes",
            volumes.len() as i64,
            vol_active,
            vol_size,
            vol_reclaimable,
        ),
    ]
    .into_iter()
    .map(|(kind, total, active, size, reclaimable)| {
        let percent = if size > 0 {
            (reclaimable as f64 / size as f64 * 100.0).round() as i64
        } else {
            0
        };
        json!({
            "Type": kind,
            "Total": total,
            "Active": active,
            "RawSize": size,
            "RawReclaimable": reclaimable,
            "TotalCount": total,
            "Size": go_size(size as f64),
            "Reclaimable": format!("{} ({percent}%)", go_size(reclaimable as f64)),
        })
    })
    .collect()
}

/// `system df`, as podman prints it.
pub fn system_df(client: &EngineClient, verbose: bool, format: Option<&str>) -> anyhow::Result<()> {
    if format.is_some() && verbose {
        anyhow::bail!("cannot combine --format and --verbose flags");
    }
    let report = velarx_shape::system::libpod_df(&client.disk_usage(false)?).value();
    if verbose {
        return df_verbose(&report);
    }
    let rows = df_summary(&report);
    let format =
        format.unwrap_or("table {{.Type}}\t{{.Total}}\t{{.Active}}\t{{.Size}}\t{{.Reclaimable}}");
    // (a row as podman's JSON has it: its fields in Go's order)
    let row_json = |r: &Value| {
        let field = |k: &str| serde_json::to_string(&r[k]).unwrap_or_default();
        format!(
            "{{\"Type\":{},\"Total\":{},\"Active\":{},\"RawSize\":{},\"RawReclaimable\":{},\"TotalCount\":{},\"Size\":{},\"Reclaimable\":{}}}",
            field("Type"),
            field("Total"),
            field("Active"),
            field("RawSize"),
            field("RawReclaimable"),
            field("TotalCount"),
            field("Size"),
            field("Reclaimable"),
        )
    };
    if format == "json" {
        // (podman's: one object a line, indented four spaces)
        let lines: Vec<String> = rows
            .iter()
            .map(|r| format!("    {}", row_json(r)))
            .collect();
        println!("[\n{}\n]", lines.join(",\n"));
        return Ok(());
    }
    if matches!(format, "{{json .}}" | "{{ json . }}") {
        for r in &rows {
            println!("{}", row_json(r));
        }
        return Ok(());
    }
    let headers = HashMap::new();
    print!(
        "{}",
        template::format_list(format, &rows, &headers).map_err(anyhow::Error::msg)?
    );
    Ok(())
}

/// `system df -v`: the images, the containers and the volumes one by one.
fn df_verbose(report: &Value) -> anyhow::Result<()> {
    let list = |k: &str| report[k].as_array().cloned().unwrap_or_default();
    let text = |v: &Value, k: &str| v[k].as_str().unwrap_or_default().to_string();
    let size = |v: &Value, k: &str| go_size(v[k].as_f64().unwrap_or(0.0));
    let since = |v: &Value| {
        let t = v["Created"]
            .as_str()
            .and_then(|c| chrono::DateTime::parse_from_rfc3339(c).ok())
            .map_or(0, |t| t.timestamp());
        human_since(t).trim_end_matches(" ago").to_string()
    };
    let short12 = |s: String| s.chars().take(12).collect::<String>();
    let mut out = String::from("Images space usage:\n\n");
    let mut rows = vec![
        "REPOSITORY\tTAG\tIMAGE ID\tCREATED\tSIZE\tSHARED SIZE\tUNIQUE SIZE\tCONTAINERS"
            .to_string(),
    ];
    for i in list("Images") {
        rows.push(format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            text(&i, "Repository"),
            text(&i, "Tag"),
            short12(text(&i, "ImageID")),
            since(&i),
            size(&i, "Size"),
            size(&i, "SharedSize"),
            size(&i, "UniqueSize"),
            i["Containers"]
        ));
    }
    out.push_str(&template::align_text(&format!("{}\n", rows.join("\n"))));
    out.push_str("\nContainers space usage:\n\n");
    let mut rows = vec![
        "CONTAINER ID\tIMAGE\tCOMMAND\tLOCAL VOLUMES\tSIZE\tCREATED\tSTATUS\tNAMES".to_string(),
    ];
    for c in list("Containers") {
        let command: Vec<&str> = c["Command"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        rows.push(format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            short12(text(&c, "ContainerID")),
            short12(text(&c, "Image")),
            command.join(" "),
            c["LocalVolumes"],
            size(&c, "RWSize"),
            since(&c),
            text(&c, "Status"),
            text(&c, "Names")
        ));
    }
    out.push_str(&template::align_text(&format!("{}\n", rows.join("\n"))));
    out.push_str("\nLocal Volumes space usage:\n\n");
    let mut rows = vec!["VOLUME NAME\tLINKS\tSIZE".to_string()];
    for v in list("Volumes") {
        rows.push(format!(
            "{}\t{}\t{}",
            text(&v, "VolumeName"),
            v["Links"],
            size(&v, "Size")
        ));
    }
    out.push_str(&template::align_text(&format!("{}\n", rows.join("\n"))));
    print!("{out}");
    Ok(())
}

/// `items` as `out` wants them; `raw`, the list as the API gave it, for
/// `--format json` (podman prints its own records, not what the templates
/// see).
fn print_list(
    out: &ListOutput,
    raw: &Value,
    items: &[Value],
    default: &str,
    headers: &HashMap<&str, &str>,
    quiet_field: &str,
) -> anyhow::Result<()> {
    if out.quiet {
        for i in items {
            println!("{}", template::text(&i[quiet_field]));
        }
        return Ok(());
    }
    let format = out.format.as_deref().unwrap_or(default);
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(raw)?);
        return Ok(());
    }
    let mut text = template::format_list(format, items, headers).map_err(anyhow::Error::msg)?;
    if out.noheading && template::Template::parse(format).is_ok_and(|t| t.is_table()) {
        text = text
            .split_once('\n')
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_default();
    }
    print!("{text}");
    Ok(())
}

/// `ps`: the containers.
pub fn containers(
    client: &EngineClient,
    all: bool,
    out: &ListOutput,
    ps: &PsArgs,
) -> anyhow::Result<()> {
    // podman's checks, in its order
    if out.quiet && (ps.size || ps.ns) {
        anyhow::bail!("quiet conflicts with size and namespace");
    }
    if ps.size && ps.ns {
        anyhow::bail!("size and namespace options conflict");
    }
    let seconds = ps.watch.unwrap_or(0);
    if seconds > 0 && ps.latest {
        anyhow::bail!("the watch and latest flags cannot be used together");
    }
    if seconds == 0 {
        return containers_once(client, all, out, ps);
    }
    // (podman clears the screen and lists again, until it is stopped)
    loop {
        print!("\x1b[2J\x1b[H");
        containers_once(client, all, out, ps)?;
        std::thread::sleep(std::time::Duration::from_secs(seconds));
    }
}

fn containers_once(
    client: &EngineClient,
    all: bool,
    out: &ListOutput,
    ps: &PsArgs,
) -> anyhow::Result<()> {
    // (podman: only a positive N limits)
    let last = ps
        .last
        .filter(|n| *n > 0)
        .map(|n| n as usize)
        .or(ps.latest.then_some(1));
    let all = all || last.is_some();
    let mut list = Value::Array(
        client
            .list_containers(all, &out.filter, ps.size, ps.ns)?
            .iter()
            .map(velarx_shape::container::libpod_list_entry)
            .collect(),
    );
    if let Some(a) = list.as_array_mut() {
        let text_of = |c: &Value, k: &str| template::text(&c[k]);
        // --last: the N made last, newest first; else the oldest first, as
        // podman's ps (the engine lists the newest first)
        if let Some(n) = last {
            a.sort_by_key(|c| std::cmp::Reverse(created_ns(&c["Created"])));
            a.truncate(n);
        } else {
            a.reverse();
        }
        // (podman's JSON has the time since the creation there, and its
        // `Status` is the state with the health after, as the column: the
        // list's own `Status` is the health alone)
        for c in a.iter_mut() {
            let since = human_since(created_ns(&c["Created"]) / 1_000_000_000);
            c["CreatedAt"] = json!(since);
            c["Status"] = json!(ps_status(c));
        }
        // --sort, as podman: ascending (created: the oldest first)
        match ps.sort.as_deref() {
            None => {}
            Some("created") => a.sort_by_key(|c| created_ns(&c["Created"])),
            Some("runningfor") => a.sort_by_key(|c| c["StartedAt"].as_i64().unwrap_or(0)),
            Some("id") => a.sort_by_key(|c| text_of(c, "Id")),
            Some("image") => a.sort_by_key(|c| text_of(c, "Image")),
            Some("names") => a.sort_by_key(|c| text_of(c, "Names")),
            Some("status") => a.sort_by_key(|c| text_of(c, "State")),
            Some("command") => a.sort_by_key(|c| text_of(c, "Command")),
            Some("pod") => a.sort_by_key(|c| text_of(c, "Pod")),
            Some(_) => anyhow::bail!(
                "invalid option for --sort, options are: command, created, id, image, names, pod, runningfor, size, or status"
            ),
        }
    }
    let items: Vec<Value> = list
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| {
            let mut v = c.as_object().cloned().unwrap_or_default();
            let id = c["Id"].as_str().unwrap_or_default();
            v.insert("ID".into(), json!(short(id, out.no_trunc)));
            let names: Vec<String> = c["Names"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|n| n.as_str().map(str::to_string))
                .collect();
            v.insert("Names".into(), json!(names.join(",")));
            let command: Vec<String> = c["Command"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|n| n.as_str().map(str::to_string))
                .collect();
            v.insert("Command".into(), json!(command.join(" ")));
            let created_ns = created_ns(&c["Created"]);
            let created = created_ns / 1_000_000_000;
            v.insert("CreatedHuman".into(), json!(human_since(created)));
            v.insert("RunningFor".into(), json!(human_since(created)));
            // (a template sees Go's time.Time, which prints in the local zone)
            v.insert(
                "CreatedAt".into(),
                json!(super::events::go_time_ns(created_ns)),
            );
            let ports: Vec<String> = c["Ports"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|p| {
                    let ip = p["host_ip"]
                        .as_str()
                        .filter(|i| !i.is_empty())
                        .unwrap_or("0.0.0.0");
                    let proto = p["protocol"].as_str().unwrap_or("tcp");
                    let (host, container) = (
                        p["host_port"].as_u64().unwrap_or(0),
                        p["container_port"].as_u64().unwrap_or(0),
                    );
                    match p["range"].as_u64().unwrap_or(1) {
                        r if r > 1 => format!(
                            "{ip}:{host}-{}->{container}-{}/{proto}",
                            host + r - 1,
                            container + r - 1
                        ),
                        _ => format!("{ip}:{host}->{container}/{proto}"),
                    }
                })
                .collect();
            let mut ports = ports;
            ports.extend(exposed_ports(&c["Ports"], &c["ExposedPorts"]));
            v.insert("Ports".into(), json!(ports.join(", ")));
            // (maps, as podman's: `{{index .Labels "k"}}`)
            for k in ["Labels", "ExposedPorts"] {
                if c[k].is_null() {
                    v.insert(k.into(), json!({}));
                }
            }
            v.insert(
                "Size".into(),
                if ps.size {
                    let rw = c["Size"]["rwSize"].as_f64().unwrap_or(0.0);
                    let root = c["Size"]["rootFsSize"].as_f64().unwrap_or(0.0);
                    json!(format!(
                        "{} (virtual {})",
                        go_size_with(rw, 3),
                        go_size_with(root, 3)
                    ))
                } else {
                    // (podman's error, and an empty column)
                    json!("")
                },
            );
            // the namespaces, as the columns of `ps --ns`
            for (field, key) in [
                ("Cgroup", "Cgroup"),
                ("IPC", "Ipc"),
                ("MNT", "Mnt"),
                ("NET", "Net"),
                ("PIDNS", "Pidns"),
                ("USERNS", "User"),
                ("UTS", "Uts"),
            ] {
                if let Some(n) = c["Namespaces"][key].as_str() {
                    v.insert(field.into(), json!(n));
                }
            }
            v.insert(
                "Pod".into(),
                json!(short(c["Pod"].as_str().unwrap_or_default(), out.no_trunc)),
            );
            v.insert(
                "PodID".into(),
                json!(short(c["Pod"].as_str().unwrap_or_default(), out.no_trunc)),
            );
            Value::Object(v)
        })
        .collect();
    let headers = HashMap::from([
        ("ID", "CONTAINER ID"),
        ("CreatedHuman", "CREATED"),
        ("RunningFor", "CREATED"),
        ("Names", "NAMES"),
        ("PodID", "POD ID"),
        ("PodName", "PODNAME"),
        ("Cgroup", "CGROUPNS"),
        ("Pid", "PID"),
    ]);
    let default = if ps.ns {
        "table {{.ID}}\t{{.Names}}\t{{.Pid}}\t{{.Cgroup}}\t{{.IPC}}\t{{.MNT}}\t{{.NET}}\t{{.PIDNS}}\t{{.USERNS}}\t{{.UTS}}"
    } else if ps.size {
        "table {{.ID}}\t{{.Image}}\t{{.Command}}\t{{.CreatedHuman}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}\t{{.Size}}"
    } else if ps.pod {
        "table {{.ID}}\t{{.Image}}\t{{.Command}}\t{{.CreatedHuman}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}\t{{.PodID}}\t{{.PodName}}"
    } else {
        "table {{.ID}}\t{{.Image}}\t{{.Command}}\t{{.CreatedHuman}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}"
    };
    print_list(out, &list, &items, default, &headers, "ID")
}

/// The exposed ports of a container of `ps` that are not published, as
/// podman's `Ports` ends with them: `NUM[-LAST]/PROTO`, consecutive ports
/// of a protocol as a range.
fn exposed_ports(published: &Value, exposed: &Value) -> Vec<String> {
    let taken: std::collections::HashSet<String> = published
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|p| {
            let first = p["container_port"].as_u64().unwrap_or(0);
            let proto = p["protocol"].as_str().unwrap_or("tcp");
            (first..first + p["range"].as_u64().unwrap_or(1).max(1))
                .map(move |port| format!("{port}/{proto}"))
        })
        .collect();
    let mut ports: Vec<(String, u16)> = exposed
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(port, protos)| Some((port.parse::<u16>().ok()?, protos)))
        .flat_map(|(port, protos)| {
            protos
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|p| p.as_str())
                .map(move |p| (p.to_string(), port))
        })
        .filter(|(proto, port)| !taken.contains(&format!("{port}/{proto}")))
        .collect();
    ports.sort();
    let mut out: Vec<String> = Vec::new();
    let mut run: Option<(String, u16, u16)> = None;
    for (proto, port) in ports {
        match &mut run {
            Some((p, _, last)) if *p == proto && u32::from(*last) + 1 == u32::from(port) => {
                *last = port
            }
            _ => {
                out.extend(run.take().map(exposed_text));
                run = Some((proto, port, port));
            }
        }
    }
    out.extend(run.map(exposed_text));
    out
}

fn exposed_text((proto, first, last): (String, u16, u16)) -> String {
    if first == last {
        format!("{first}/{proto}")
    } else {
        format!("{first}-{last}/{proto}")
    }
}

/// `images`: one row per name of an image.
pub fn images(
    client: &EngineClient,
    all: bool,
    out: &ListOutput,
    args: &ImagesArgs,
) -> anyhow::Result<()> {
    let mut filters = out.filter.clone();
    if let Some(image) = &args.image {
        filters.push(format!("reference={image}"));
    }
    // (both values of the filter: the images of the store and the pulls)
    if args.lazy
        && !filters
            .iter()
            .any(|f| f.starts_with("lazy=") || f.starts_with("lazy!="))
    {
        filters.extend(["lazy=true".into(), "lazy=false".into()]);
    }
    let records = client.list_images(all, &filters)?;
    let (list, items, default) = image_rows(&records, out, args)?;
    print_list(out, &list, &items, &default, &image_headers(), "ID")
}

/// The headers of the columns of `images` that are not their field's name.
fn image_headers() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("ID", "IMAGE ID"),
        ("CreatedSince", "CREATED"),
        ("LazyColumn", "LAZY"),
    ])
}

/// The list of `images` for `--format json`, its rows for a template and
/// its default template.
fn image_rows(
    records: &[velarx_proto::workload::ImageRecord],
    out: &ListOutput,
    args: &ImagesArgs,
) -> anyhow::Result<(Value, Vec<Value>, String)> {
    let list = Value::Array(
        records
            .iter()
            .map(|r| {
                let mut i = velarx_shape::image::libpod_summary(r);
                let created = i["Created"].as_i64().unwrap_or(0);
                i["CreatedAt"] = json!(chrono::DateTime::from_timestamp(created, 0)
                    .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                    .unwrap_or_default());
                // what velarx knows of its images and podman does not: a
                // pull in progress (`--format '{{.Lazy}}'`)
                i["Lazy"] = json!(r.lazy);
                i
            })
            .collect(),
    );
    let mut rows: Vec<(Value, i64, i64)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for img in list.as_array().into_iter().flatten() {
        let id = img["Id"].as_str().unwrap_or_default();
        // what velarx knows of its images and podman does not: where from
        // (`--format '{{.Source}}'`)
        let source = "local".to_string();
        let created = img["Created"].as_i64().unwrap_or(0);
        let mut tags: Vec<String> = img["RepoTags"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|t| t.as_str().map(str::to_string))
            .collect();
        // (an image pulled by digest has the repository it came from)
        if tags.is_empty() {
            for d in img["RepoDigests"].as_array().into_iter().flatten() {
                if let Some((repo, _)) = d.as_str().and_then(|d| d.split_once('@')) {
                    let row = format!("{repo}:<none>");
                    if !tags.contains(&row) {
                        tags.push(row);
                    }
                }
            }
        }
        if tags.is_empty() {
            tags.push("<none>:<none>".into());
        }
        for t in tags {
            // the tag is after the last colon that is not in a port
            let (repo, tag) = match t.rsplit_once(':') {
                Some((r, tg)) if !tg.contains('/') => (r.to_string(), tg.to_string()),
                _ => (t.clone(), "latest".to_string()),
            };
            let mut v = img.as_object().cloned().unwrap_or_default();
            // podman sends it only when it is (an additional image store)
            v.entry("ReadOnly").or_insert(json!(false));
            v.insert(
                "ID".into(),
                json!(image_id(id, &img["Digest"], out.no_trunc)),
            );
            v.insert("Repository".into(), json!(repo));
            v.insert("Tag".into(), json!(tag));
            v.insert("Source".into(), json!(source));
            let lazy = img["Lazy"].as_bool().unwrap_or(false);
            v.insert("LazyColumn".into(), json!(if lazy { "yes" } else { "no" }));
            // (podman's template prints the names it had joined)
            let history: Vec<&str> = img["History"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            v.insert("History".into(), json!(history.join(", ")));
            // (a template sees the duration, `json` the Unix time)
            v.insert("Created".into(), json!(human_since(created)));
            v.insert("CreatedSince".into(), json!(human_since(created)));
            let created_at = json!(chrono::DateTime::from_timestamp(created, 0)
                .map(|t| t.format("%Y-%m-%d %H:%M:%S +0000 UTC").to_string())
                .unwrap_or_default());
            v.insert("CreatedAt".into(), created_at.clone());
            v.insert("CreatedTime".into(), created_at);
            v.insert(
                "IsDangling".into(),
                json!(img["Dangling"].as_bool().unwrap_or(false)),
            );
            v.insert(
                "IsReadOnly".into(),
                json!(img["ReadOnly"].as_bool().unwrap_or(false)),
            );
            v.insert(
                "Size".into(),
                json!(human_size(img["Size"].as_f64().unwrap_or(0.0))),
            );
            if !out.quiet || seen.insert(id.to_string()) {
                rows.push((Value::Object(v), created, img["Size"].as_i64().unwrap_or(0)));
            }
        }
    }
    // as podman: the newest first by default, else ascending
    let text = |v: &Value, k: &str| v[k].as_str().unwrap_or_default().to_string();
    match args.sort.as_deref().unwrap_or("created") {
        "created" => rows.sort_by_key(|r| std::cmp::Reverse(r.1)),
        "id" => rows.sort_by_key(|r| text(&r.0, "ID")),
        "repository" => rows.sort_by_key(|r| (text(&r.0, "Repository"), text(&r.0, "Tag"))),
        "tag" => rows.sort_by_key(|r| text(&r.0, "Tag")),
        "size" => rows.sort_by_key(|r| r.2),
        other => anyhow::bail!(
            "invalid argument \"{other}\" for \"--sort\" flag: must be one of \"created, id, repository, size, tag\""
        ),
    }
    let items: Vec<Value> = rows.into_iter().map(|r| r.0).collect();
    let mut default = String::from("table {{.Repository}}\t{{.Tag}}");
    if args.digests {
        default.push_str("\t{{.Digest}}");
    }
    default.push_str("\t{{.ID}}\t{{.CreatedSince}}\t{{.Size}}");
    if args.history {
        default.push_str("\t{{if .History}}{{.History}}{{else}}<none>{{end}}");
    }
    if args.lazy {
        default.push_str("\t{{.LazyColumn}}");
    }
    Ok((list, items, default))
}

/// `volume ls`.
pub fn volumes(client: &EngineClient, out: &ListOutput) -> anyhow::Result<()> {
    let list = client.podman_list(Kind::Volume, false, &out.filter)?;
    let items: Vec<Value> = list
        .as_array()
        .into_iter()
        .flatten()
        .map(|v| {
            let mut v = v.clone();
            go_fields(Kind::Volume, &mut v);
            // (podman's list entry is the inspect data, embedded twice)
            let data = v.clone();
            v["InspectVolumeData"] = data.clone();
            v["VolumeConfigResponse"] = json!({ "InspectVolumeData": data });
            v
        })
        .collect();
    let headers = HashMap::from([("Name", "VOLUME NAME")]);
    print_list(
        out,
        &list,
        &items,
        "table {{.Driver}}\t{{.Name}}",
        &headers,
        "Name",
    )
}

/// `network ls`.
pub fn networks(client: &EngineClient, out: &ListOutput) -> anyhow::Result<()> {
    let list = client.podman_list(Kind::Network, false, &out.filter)?;
    let items: Vec<Value> = list
        .as_array()
        .into_iter()
        .flatten()
        .map(|n| {
            let mut v = n.as_object().cloned().unwrap_or_default();
            let id = n["id"].as_str().unwrap_or_default();
            network_go_fields(&mut v);
            v.remove("Network");
            v.insert("ID".into(), json!(short(id, out.no_trunc)));
            Value::Object(v)
        })
        .collect();
    let headers = HashMap::from([("ID", "NETWORK ID")]);
    print_list(
        out,
        &list,
        &items,
        "table {{.ID}}\t{{.Name}}\t{{.Driver}}",
        &headers,
        "name",
    )
}

/// The options of `pod ps` besides the output options.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct PodPsArgs {
    /// Display the container UUIDs (truncated without --no-trunc)
    #[arg(long)]
    pub ctr_ids: bool,
    /// Display the container names
    #[arg(long)]
    pub ctr_names: bool,
    /// Display the container status
    #[arg(long)]
    pub ctr_status: bool,
    /// Display the cgroup parent and the namespaces of the pod
    #[arg(long, alias = "namespace")]
    pub ns: bool,
    /// Sort by created (the newest first), id, name, number or status
    #[arg(long, default_value = "created")]
    pub sort: String,
    /// List the pod made last only
    #[arg(long, short = 'l')]
    pub latest: bool,
}

/// `pod ps`.
pub fn pods(client: &EngineClient, out: &ListOutput, ps: &PodPsArgs) -> anyhow::Result<()> {
    if out.quiet && out.format.as_deref().is_some_and(|f| !f.is_empty()) {
        anyhow::bail!("quiet and format cannot be used together");
    }
    if let Some(f) = out.filter.iter().find(|f| !f.contains('=')) {
        anyhow::bail!("filter input must be in the form of filter=value: {f} is invalid");
    }
    let mut pods: Vec<Value> = client
        .podman_list(Kind::Pod, false, &out.filter)?
        .as_array()
        .cloned()
        .unwrap_or_default();
    let containers = |p: &Value| p["Containers"].as_array().map_or(0, Vec::len);
    match ps.sort.as_str() {
        "created" => pods.sort_by_key(|p| std::cmp::Reverse(created_ns(&p["Created"]))),
        "id" => pods.sort_by_key(|p| template::text(&p["Id"])),
        "name" => pods.sort_by_key(|p| template::text(&p["Name"])),
        "number" => pods.sort_by_key(containers),
        "status" => pods.sort_by_key(|p| template::text(&p["Status"])),
        _ => anyhow::bail!(
            "invalid option for --sort, options are: created, id, name, number, or status"
        ),
    }
    if ps.latest {
        pods.sort_by_key(|p| std::cmp::Reverse(created_ns(&p["Created"])));
        pods.truncate(1);
    }
    let list = Value::Array(pods);
    let items: Vec<Value> = list
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| {
            let mut v = p.as_object().cloned().unwrap_or_default();
            let id = json!(short(p["Id"].as_str().unwrap_or_default(), out.no_trunc));
            v.insert("Id".into(), id.clone());
            v.insert("ID".into(), id);
            let infra = json!(short(
                p["InfraId"].as_str().unwrap_or_default(),
                out.no_trunc
            ));
            v.insert("InfraId".into(), infra.clone());
            v.insert("InfraID".into(), infra);
            v.insert("NumberOfContainers".into(), json!(containers(p)));
            let members = |key: &str, trunc: bool| -> String {
                p["Containers"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|c| {
                        let text = template::text(&c[key]);
                        if trunc {
                            short(&text, out.no_trunc)
                        } else {
                            text
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            };
            v.insert("ContainerIds".into(), json!(members("Id", true)));
            v.insert("ContainerNames".into(), json!(members("Names", false)));
            v.insert("ContainerStatuses".into(), json!(members("Status", false)));
            let restarts: i64 = p["Containers"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|c| c["RestartCount"].as_i64().unwrap_or(0))
                .sum();
            v.insert("Restarts".into(), json!(restarts.to_string()));
            let networks: Vec<String> = p["Networks"]
                .as_array()
                .into_iter()
                .flatten()
                .map(template::text)
                .collect();
            v.insert("Networks".into(), json!(networks.join(",")));
            if let Some(created) = p["Created"]
                .as_str()
                .and_then(|c| chrono::DateTime::parse_from_rfc3339(c).ok())
            {
                v.insert("Created".into(), json!(human_since(created.timestamp())));
            }
            Value::Object(v)
        })
        .collect();
    let headers = HashMap::from([
        ("Id", "POD ID"),
        ("ID", "POD ID"),
        ("InfraID", "INFRA ID"),
        ("InfraId", "INFRA ID"),
        ("NumberOfContainers", "# OF CONTAINERS"),
        ("ContainerIds", "IDS"),
        ("ContainerNames", "NAMES"),
        ("ContainerStatuses", "STATUS"),
        ("Namespace", "NAMESPACES"),
    ]);
    // (podman's row: what the flags add before the number of containers)
    let mut row = vec![
        "{{.Id}}",
        "{{.Name}}",
        "{{.Status}}",
        "{{.Created}}",
        "{{.InfraID}}",
    ];
    for (given, field) in [
        (ps.ctr_ids, "{{.ContainerIds}}"),
        (ps.ctr_names, "{{.ContainerNames}}"),
        (ps.ctr_status, "{{.ContainerStatuses}}"),
    ] {
        if given {
            row.push(field);
        }
    }
    if ps.ns {
        row.extend(["{{.Cgroup}}", "{{.Namespace}}"]);
    }
    if !(ps.ctr_ids || ps.ctr_names || ps.ctr_status) {
        row.push("{{.NumberOfContainers}}");
    }
    // (podman's -q has the whole IDs)
    if out.quiet {
        for p in list.as_array().into_iter().flatten() {
            println!("{}", template::text(&p["Id"]));
        }
        return Ok(());
    }
    print_list(
        out,
        &list,
        &items,
        &format!("table {}", row.join("\t")),
        &headers,
        "Id",
    )
}

/// The kind an `inspect --type` names: `None` for all of them.
pub fn kind_of_type(t: &str) -> Option<Option<Kind>> {
    Some(match t {
        "all" | "" => None,
        "container" => Some(Kind::Container),
        "image" => Some(Kind::Image),
        "volume" => Some(Kind::Volume),
        "network" => Some(Kind::Network),
        "pod" => Some(Kind::Pod),
        _ => return None,
    })
}

/// What podman says of an object of `kind` named `name` that is not there.
pub fn podman_missing(kind: Kind, name: &str) -> String {
    match kind {
        Kind::Container => format!("no such container \"{name}\""),
        Kind::Image => format!("{name}: image not known"),
        Kind::Volume => format!("no volume with name \"{name}\" found: no such volume"),
        // (podman's inspect names the network first)
        Kind::Network => {
            format!(
                "network {name}: unable to find network with name or ID {name}: network not found"
            )
        }
        Kind::Pod => format!("no such pod {name}"),
    }
}

/// What podman says of a pod that is not there, for commands that name
/// pods by name or ID.
pub fn podman_missing_pod(name: &str) -> String {
    format!("no pod with name or ID {name} found: no such pod")
}

/// Whether the engine refused an image reference before looking for it
/// (podman's words), which is not the image being missing.
pub fn refused_image(e: &crate::client::ClientError) -> bool {
    e.is(Condition::InvalidReference) || e.is(Condition::NeedsForce)
}

/// The message of an error of the inspect of `name`: podman's when it is
/// not there, else the error's.
pub fn missing_message(kind: Kind, name: &str, e: &crate::client::ClientError) -> String {
    if e.is_not_found() && !(kind == Kind::Image && refused_image(e)) {
        podman_missing(kind, name)
    } else {
        e.to_string()
    }
}

/// The fields of podman's InspectPodData under the names a template uses:
/// the document has them by their JSON names (`cpu_period`), and a field that
/// is not there is the zero of its type.
fn pod_go_fields(doc: &mut Value) {
    const NUMBERS: [(&str, &str); 6] = [
        ("CPUPeriod", "cpu_period"),
        ("CPUQuota", "cpu_quota"),
        ("CPUShares", "cpu_shares"),
        ("MemoryLimit", "memory_limit"),
        ("MemorySwap", "memory_swap"),
        ("BlkioWeight", "blkio_weight"),
    ];
    const TEXTS: [(&str, &str); 2] = [("CPUSetCPUs", "cpuset_cpus"), ("CPUSetMems", "cpuset_mems")];
    const LISTS: [(&str, &str); 6] = [
        ("Mounts", "mounts"),
        ("Devices", "devices"),
        ("BlkioDeviceReadBps", "device_read_bps"),
        ("BlkioDeviceWriteBps", "device_write_bps"),
        ("VolumesFrom", "volumes_from"),
        ("SecurityOpts", "security_opt"),
    ];
    let Some(o) = doc.as_object_mut() else {
        return;
    };
    let whole = Value::Object(o.clone());
    for (go, key) in NUMBERS {
        let v = o.get(key).cloned().unwrap_or(json!(0));
        o.insert(go.into(), v);
    }
    for (go, key) in TEXTS {
        let v = o.get(key).cloned().unwrap_or(json!(""));
        o.insert(go.into(), v);
    }
    for (go, key) in LISTS {
        let v = o.get(key).cloned().unwrap_or(json!([]));
        o.insert(go.into(), v);
    }
    let weight = o.get("blkio_weight_device").cloned().unwrap_or(json!([]));
    o.insert("BlkioWeightDevice".into(), weight);
    o.entry("RestartPolicy").or_insert(json!(""));
    // (what the JSON leaves out is Go's zero value: a nil map, an empty text)
    o.entry("Labels").or_insert(json!({}));
    o.entry("Namespace").or_insert(json!(""));
    o.insert("InspectPodData".into(), whole);
    if let Some(infra) = o.get_mut("InfraConfig").and_then(Value::as_object_mut) {
        // (a nil list prints as [])
        for key in ["DNSServer", "DNSSearch", "DNSOption", "HostAdd"] {
            if infra.get(key).is_some_and(Value::is_null) {
                infra.insert(key.into(), json!([]));
            }
        }
        for (go, key) in [
            ("CPUPeriod", "cpu_period"),
            ("CPUQuota", "cpu_quota"),
            ("CPUSetCPUs", "cpuset_cpus"),
            ("PidNS", "pid_ns"),
            ("UserNS", "userns"),
            ("UtsNS", "uts_ns"),
        ] {
            let zero = if go.starts_with("CPU") && go != "CPUSetCPUs" {
                json!(0)
            } else {
                json!("")
            };
            let v = infra.get(key).cloned().unwrap_or(zero);
            infra.insert(go.into(), v);
        }
    }
}

/// `inspect`: the objects `names` (of `kind`, or the first kind that has
/// one), as podman's JSON array or through `--format`.  The names not
/// found are said on the standard error; false if there were some.
pub fn inspect(
    client: &EngineClient,
    kind: Option<Kind>,
    names: &[String],
    format: Option<&str>,
    size: bool,
) -> anyhow::Result<bool> {
    let kinds: Vec<Kind> = match kind {
        Some(k) => vec![k],
        None => vec![
            Kind::Container,
            Kind::Image,
            Kind::Volume,
            Kind::Network,
            Kind::Pod,
        ],
    };
    let mut found = Vec::new();
    let mut missing = Vec::new();
    // (a reference refused before it is looked up is said as it is, and
    // alone: podman stops at it)
    let mut refused = false;
    for name in names {
        let mut errors = Vec::new();
        let v = kinds.iter().find_map(|k| {
            match k {
                Kind::Container if size => client.podman_inspect_sized(name),
                _ => client.podman_inspect(*k, name),
            }
            .map_err(|e| errors.push(e))
            .ok()
            .map(|v| (*k, v))
        });
        // (a failure of the daemon is not an object that is not there: its
        // words, and the exit status of a failure)
        if v.is_none() {
            if let Some(i) = errors.iter().position(|e| e.is_server_error()) {
                return Err(errors.swap_remove(i).into());
            }
        }
        match v {
            Some(v) => found.push(v),
            None => {
                let message = match (kind, errors.first()) {
                    (Some(Kind::Image), Some(e)) if refused_image(e) => {
                        refused = true;
                        e.to_string()
                    }
                    (Some(k), _) => podman_missing(k, name),
                    (None, _) => format!("no such object: \"{name}\""),
                };
                missing.push(message);
            }
        }
    }
    match format {
        _ if found.is_empty() && refused => {}
        None | Some("json") => {
            let found: Vec<Value> = found.into_iter().map(|(_, v)| v).collect();
            println!("{}", serde_json::to_string_pretty(&Value::Array(found))?);
        }
        Some(f) => {
            let t = template::Template::parse(f).map_err(anyhow::Error::msg)?;
            for (kind, v) in &found {
                // (a template sees Go's time.Duration, which prints as 6s)
                let mut v = v.clone();
                durations_as_go(&mut v);
                go_fields(*kind, &mut v);
                if *kind == Kind::Pod {
                    pod_go_fields(&mut v);
                }
                let s = t.render(&v).map_err(anyhow::Error::msg)?;
                println!("{s}");
            }
        }
    }
    // (after what was found, as podman)
    use std::io::Write;
    let _ = std::io::stdout().flush();
    for message in &missing {
        eprintln!("Error: {message}");
    }
    Ok(missing.is_empty())
}

/// What a template sees of a container that its JSON does not show: the
/// durations of the health checks are Go's `time.Duration` (nanoseconds in
/// the JSON, `6s` printed).
fn durations_as_go(v: &mut Value) {
    for (section, keys) in [
        (
            "Healthcheck",
            &["Interval", "Timeout", "StartPeriod", "StartInterval"][..],
        ),
        (
            "StartupHealthCheck",
            &["Interval", "Timeout", "StartPeriod"][..],
        ),
    ] {
        let Some(h) = v.pointer_mut(&format!("/Config/{section}")) else {
            continue;
        };
        for k in keys {
            if let Some(ns) = h[*k].as_i64() {
                h[*k] = template::go_duration_value(ns);
            }
        }
    }
}

/// The fields of podman's inspect structures that its JSON leaves out
/// when they are empty, as a template sees them.
fn go_fields(kind: Kind, v: &mut Value) {
    let Some(o) = v.as_object_mut() else {
        return;
    };
    match kind {
        Kind::Volume => {
            o.entry("Status").or_insert(json!({}));
            o.entry("StorageID").or_insert(json!(""));
            o.entry("Timeout").or_insert(json!(0));
            o.entry("UID").or_insert(json!(0));
            o.entry("GID").or_insert(json!(0));
            o.entry("Anonymous").or_insert(json!(false));
        }
        Kind::Pod => {
            o.entry("CreateCommand").or_insert(json!([]));
            o.entry("Labels").or_insert(json!({}));
        }
        Kind::Network => network_go_fields(o),
        // (`SizeRw` is a pointer: `<nil>` without --size)
        Kind::Container => {
            o.entry("SizeRootFs").or_insert(json!(0));
        }
        _ => {}
    }
}

/// The fields of a network that podman's JSON leaves out when they are
/// empty, and the network itself (`.Network` of its inspect).
fn network_go_fields(o: &mut Map<String, Value>) {
    o.entry("network_dns_servers").or_insert(json!([]));
    o.entry("routes").or_insert(json!([]));
    o.entry("options").or_insert(json!({}));
    o.entry("labels").or_insert(json!({}));
    let whole = Value::Object(o.clone());
    o.insert("Network".into(), whole);
}

/// `info --format`: podman's information; a template sees its lists that
/// are nil in the JSON as Go prints them, `[]`.
pub fn info(v: &Value, format: &str) -> anyhow::Result<()> {
    if format == "json" {
        return one(v, format);
    }
    let mut v = v.clone();
    if v.pointer("/plugins/authorization")
        .is_some_and(Value::is_null)
    {
        v["plugins"]["authorization"] = json!([]);
    }
    one(&v, format)
}

/// `info --format`, `version`: one object through a template.
pub fn one(v: &Value, format: &str) -> anyhow::Result<()> {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(v)?);
        return Ok(());
    }
    let t = template::Template::parse(format).map_err(anyhow::Error::msg)?;
    println!("{}", t.render(v).map_err(anyhow::Error::msg)?);
    Ok(())
}

/// A document as podman prints its YAML (`info`): go-yaml's layout, the
/// lists at the indent of their key, the strings quoted only when they
/// would read as something else.
pub fn go_yaml(v: &Value) -> String {
    fn scalar(v: &Value) -> String {
        let Value::String(s) = v else {
            return match v {
                Value::Null => "null".into(),
                v => v.to_string(),
            };
        };
        let plain_other = matches!(
            s.to_ascii_lowercase().as_str(),
            "true" | "false" | "yes" | "no" | "on" | "off" | "y" | "n" | "null" | "~"
        ) || s.parse::<f64>().is_ok();
        if s.is_empty() || plain_other || s.contains(['\n', '\t', '\\']) {
            return serde_json::to_string(s).unwrap_or_default();
        }
        let special = s.starts_with(|c: char| "-?:,[]{}#&*!|>'\"%@`".contains(c))
            || s.starts_with(' ')
            || s.ends_with([' ', ':'])
            || s.contains(": ")
            || s.contains(" #");
        if special {
            format!("'{}'", s.replace('\'', "''"))
        } else {
            s.clone()
        }
    }
    fn block(v: &Value, indent: usize, out: &mut String) {
        let pad = " ".repeat(indent);
        match v {
            Value::Object(o) => {
                for (k, v) in o {
                    match v {
                        Value::Object(m) if !m.is_empty() => {
                            out.push_str(&format!("{pad}{k}:\n"));
                            block(v, indent + 2, out);
                        }
                        Value::Array(a) if !a.is_empty() => {
                            out.push_str(&format!("{pad}{k}:\n"));
                            block(v, indent, out);
                        }
                        Value::Object(_) => out.push_str(&format!("{pad}{k}: {{}}\n")),
                        Value::Array(_) => out.push_str(&format!("{pad}{k}: []\n")),
                        v => out.push_str(&format!("{pad}{k}: {}\n", scalar(v))),
                    }
                }
            }
            Value::Array(a) => {
                for item in a {
                    match item {
                        Value::Object(m) if !m.is_empty() => {
                            // (the first key after the dash, the others under it)
                            let mut inner = String::new();
                            block(item, indent + 2, &mut inner);
                            out.push_str(&format!("{pad}- {}", &inner[indent + 2..]));
                        }
                        Value::Array(_) | Value::Object(_) => {
                            let mut inner = String::new();
                            block(item, indent + 2, &mut inner);
                            out.push_str(&format!("{pad}-\n{inner}"));
                        }
                        v => out.push_str(&format!("{pad}- {}\n", scalar(v))),
                    }
                }
            }
            v => out.push_str(&format!("{pad}{}\n", scalar(v))),
        }
    }
    let mut out = String::new();
    block(v, 0, &mut out);
    out
}

/// podman's `version` without --format.
const VERSION_TEMPLATE: &str = r#"{{with .Client -}}
Client:\tPodman Engine
Version:\t{{.Version}}
API Version:\t{{.APIVersion}}
Go Version:\t{{.GoVersion}}
{{if .GitCommit -}}Git Commit:\t{{.GitCommit}}\n{{end -}}
Built:\t{{.BuiltTime}}
OS/Arch:\t{{.OsArch}}
{{- end}}

{{- if .Server }}{{with .Server}}

Server:\tPodman Engine
Version:\t{{.Version}}
API Version:\t{{.APIVersion}}
Go Version:\t{{.GoVersion}}
{{if .GitCommit -}}Git Commit:\t{{.GitCommit}}\n{{end -}}
Built:\t{{.BuiltTime}}
OS/Arch:\t{{.OsArch}}
{{- end}}{{- end}}
"#;

/// The text of `version` as podman prints it.
pub fn version_text(v: &Value) -> anyhow::Result<String> {
    let t = template::Template::parse(VERSION_TEMPLATE).map_err(anyhow::Error::msg)?;
    Ok(template::align_text(
        &t.render(v).map_err(anyhow::Error::msg)?,
    ))
}

/// A build time as podman's `version` prints it (Go's ANSIC layout).
fn built_time(t: chrono::DateTime<chrono::Utc>) -> String {
    t.with_timezone(&chrono::Local)
        .format("%a %b %e %H:%M:%S %Y")
        .to_string()
}

/// When this program was built: the build time it was given, else when its
/// file was made.
fn client_built() -> Option<chrono::DateTime<chrono::Utc>> {
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(velarx_base::buildinfo::time()) {
        return Some(t.with_timezone(&chrono::Utc));
    }
    let modified = std::env::current_exe()
        .ok()?
        .metadata()
        .ok()?
        .modified()
        .ok()?;
    Some(modified.into())
}

/// `version`: the client's and the server's, with podman's fields.
pub fn version(client: Option<&EngineClient>) -> Value {
    let mut v = Map::new();
    let built = client_built();
    v.insert(
        "Client".into(),
        json!({
            "Version": env!("CARGO_PKG_VERSION"),
            "APIVersion": API_VERSION,
            "GoVersion": "rust",
            "GitCommit": option_env!("GIT_COMMIT").unwrap_or(""),
            "BuiltTime": built.map(built_time).unwrap_or_default(),
            "Built": built.map(|t| t.timestamp()).unwrap_or(0),
            // who built it, as the packager names itself
            "BuildOrigin": option_env!("VELARX_BUILD_ORIGIN").unwrap_or(""),
            "Os": "linux",
            "OsArch": format!(
                "linux/{}",
                velarx_shape::system::go_arch(std::env::consts::ARCH)
            ),
        }),
    );
    if let Some(server) = client.and_then(|cl| cl.version_inspect().ok()) {
        v.insert("Server".into(), server_version(&server));
    }
    Value::Object(v)
}

/// The API version the client speaks (the server's).
const API_VERSION: &str = velarx_shape::system::LIBPOD_VERSION;

/// podman's `Server` of `version`, of the engine's build.
fn server_version(server: &velarx_proto::system::VersionRecord) -> Value {
    let built = (server.built_ns > 0)
        .then(|| chrono::DateTime::<chrono::Utc>::from_timestamp_nanos(server.built_ns));
    json!({
        "Version": server.version,
        "APIVersion": API_VERSION,
        "GoVersion": "rust",
        "GitCommit": server.commit,
        "BuiltTime": built.map(built_time).unwrap_or_default(),
        "Built": built.map(|t| t.timestamp()).unwrap_or(0),
        "Os": server.os,
        "OsArch": format!("{}/{}", server.os, velarx_shape::system::go_arch(&server.arch)),
    })
}

/// The lines of `port`: each published port of `inspect` (a container's
/// podman JSON), `private` (`80` or `80/tcp`) only if given.
pub fn port_lines(inspect: &Value, private: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    let Some(ports) = inspect
        .pointer("/NetworkSettings/Ports")
        .and_then(Value::as_object)
    else {
        return out;
    };
    let mut keys: Vec<&String> = ports.keys().collect();
    keys.sort_by_key(|k| {
        let (n, p) = k.split_once('/').unwrap_or((k.as_str(), "tcp"));
        (n.parse::<u32>().unwrap_or(0), p.to_string())
    });
    for k in keys {
        if let Some(want) = private {
            let want = if want.contains('/') {
                want.to_string()
            } else {
                format!("{want}/tcp")
            };
            if *k != want {
                continue;
            }
        }
        for b in ports[k].as_array().into_iter().flatten() {
            let ip = b["HostIp"]
                .as_str()
                .filter(|i| !i.is_empty())
                .unwrap_or("0.0.0.0");
            let port = template::text(&b["HostPort"]);
            if private.is_some() {
                out.push(format!("{ip}:{port}"));
            } else {
                out.push(format!("{k} -> {ip}:{port}"));
            }
        }
    }
    out
}

/// `history`: the layers of an image, newest first.
pub fn history(
    client: &EngineClient,
    image: &str,
    out: &ListOutput,
    human: bool,
) -> anyhow::Result<()> {
    let list = Value::Array(
        client
            .image_history(image)?
            .iter()
            .map(|h| velarx_shape::image::history(h, false))
            .collect(),
    );
    let names = list
        .as_array()
        .and_then(|a| a.iter().find(|h| h["Tags"].is_array()))
        .map_or_else(|| json!([]), |h| h["Tags"].clone());
    let items: Vec<Value> = list
        .as_array()
        .into_iter()
        .flatten()
        .map(|h| {
            let mut v = h.as_object().cloned().unwrap_or_default();
            let id = h["Id"].as_str().unwrap_or("<missing>");
            v.insert(
                "ID".into(),
                json!(if id == "<missing>" {
                    id.to_string()
                } else {
                    short(id, out.no_trunc)
                }),
            );
            let created = h["Created"].as_i64().unwrap_or(0);
            v.insert(
                "Created".into(),
                json!(if human {
                    human_since(created)
                } else {
                    chrono::DateTime::from_timestamp(created, 0)
                        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                        .unwrap_or_default()
                }),
            );
            v.insert("CreatedSince".into(), json!(human_since(created)));
            v.insert(
                "CreatedAt".into(),
                json!(chrono::DateTime::from_timestamp(created, 0)
                    .map(|t| t
                        .with_timezone(&chrono::Local)
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_default()),
            );
            // as podman: the names of the image on every row
            v.insert("Tags".into(), names.clone());
            let by = h["CreatedBy"].as_str().unwrap_or_default();
            let by = if out.no_trunc || by.chars().count() <= 45 {
                by.to_string()
            } else {
                format!("{}...", by.chars().take(42).collect::<String>())
            };
            v.insert("CreatedBy".into(), json!(by));
            let size = h["Size"].as_f64().unwrap_or(0.0);
            v.insert(
                "Size".into(),
                json!(if human {
                    // (podman's three significant digits)
                    go_size_with(size, 3)
                } else {
                    format!("{}", size as u64)
                }),
            );
            Value::Object(v)
        })
        .collect();
    // podman's JSON of history: its own fields, not the API's
    let raw: Vec<Value> = list
        .as_array()
        .into_iter()
        .flatten()
        .map(|h| {
            let id = h["Id"].as_str().unwrap_or("<missing>");
            json!({
                "id": velarx_shape::without_algorithm(id),
                "created": chrono::DateTime::from_timestamp(h["Created"].as_i64().unwrap_or(0), 0)
                    .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_default(),
                "CreatedBy": h["CreatedBy"],
                "size": h["Size"].as_i64().unwrap_or(0),
                "comment": h["Comment"].as_str().unwrap_or_default(),
                "tags": names.clone(),
            })
        })
        .collect();
    let headers = HashMap::from([("CreatedBy", "CREATED BY")]);
    print_list(
        out,
        &Value::Array(raw),
        &items,
        "table {{.ID}}\t{{.Created}}\t{{.CreatedBy}}\t{{.Size}}\t{{.Comment}}",
        &headers,
        "ID",
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn image_ids_in_lists_are_podmans() {
        let whole = "ab".repeat(32);
        let digest = json!(format!("sha256:{whole}"));
        assert_eq!(image_id(&whole, &digest, false), whole[..12]);
        assert_eq!(image_id(&whole, &digest, true), format!("sha256:{whole}"));
        // an id of 12 digits, from before ids were whole
        assert_eq!(image_id(&whole[..12], &digest, false), whole[..12]);
        assert_eq!(
            image_id(&whole[..12], &digest, true),
            format!("sha256:{whole}")
        );
        assert_eq!(
            image_id("abcdefabcdef", &Value::Null, true),
            "sha256:abcdefabcdef"
        );
        let e = |c: Condition, m: &str| crate::client::ClientError::refused(c, m.into());
        assert!(refused_image(&e(
            Condition::InvalidReference,
            "ab: any words"
        )));
        assert!(refused_image(&e(Condition::NeedsForce, "any words")));
        // (the words of a refusal in another condition, or in an image that
        // is called so, are not one)
        for c in [Condition::NoSuchImage, Condition::Failed] {
            assert!(!refused_image(&e(
                c,
                "sha256:ab: invalid format: no 64-byte hexadecimal value"
            )));
        }
        assert!(!refused_image(&crate::client::ClientError::api(
            404,
            "repository name must be lowercase".into()
        )));
    }

    use super::*;

    #[test]
    fn images_tell_the_pulls_in_progress_with_lazy() {
        let image = |id: &str, name: &str, lazy| velarx_proto::workload::ImageRecord {
            id: id.repeat(64),
            names: vec![name.into()],
            lazy,
            ..Default::default()
        };
        let records = [
            image("a", "x/stored:1", false),
            image("b", "x/pulling:2", true),
        ];
        let table = |args: &ImagesArgs| {
            let (_, items, default) = image_rows(&records, &ListOutput::default(), args).unwrap();
            template::format_list(&default, &items, &image_headers()).unwrap()
        };
        let columns = |line: &str| -> Vec<String> {
            line.split("  ")
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(str::to_string)
                .collect()
        };
        let plain = table(&ImagesArgs::default());
        assert_eq!(
            columns(plain.lines().next().unwrap()),
            ["REPOSITORY", "TAG", "IMAGE ID", "CREATED", "SIZE"]
        );
        let lazy = table(&ImagesArgs {
            lazy: true,
            ..Default::default()
        });
        let rows: Vec<Vec<String>> = lazy.lines().map(columns).collect();
        assert_eq!(rows[0].last().unwrap(), "LAZY", "{lazy}");
        let last = |name: &str| rows.iter().find(|r| r[0] == name).unwrap().last().cloned();
        assert_eq!(last("x/stored").unwrap(), "no", "{lazy}");
        assert_eq!(last("x/pulling").unwrap(), "yes", "{lazy}");
        // the field of a template and of `--format json`: a bool
        let (list, items, _) =
            image_rows(&records, &ListOutput::default(), &ImagesArgs::default()).unwrap();
        assert_eq!(list[0]["Lazy"], json!(false));
        assert_eq!(list[1]["Lazy"], json!(true));
        let lazies = template::format_list("{{.Repository}} {{.Lazy}}", &items, &image_headers());
        assert_eq!(lazies.unwrap(), "x/stored false\nx/pulling true\n");
    }

    #[test]
    fn human_forms() {
        let now = chrono::Utc::now().timestamp();
        assert_eq!(human_since(now - 30), "30 seconds ago");
        assert_eq!(human_since(now - 90), "About a minute ago");
        assert_eq!(human_since(now - 600), "10 minutes ago");
        assert_eq!(human_since(now - 3 * 86400), "3 days ago");
        assert_eq!(human_size(7_840_000.0), "7.84 MB");
        assert_eq!(human_size(512.0), "512 B");
        assert_eq!(human_size(1_000.0), "1 kB");
        assert_eq!(human_size(123_400_000.0), "123 MB");
        assert_eq!(short("sha256:0123456789abcdef", false), "0123456789ab");
        assert_eq!(
            created_ns(&json!("2026-01-02T03:04:05.000000123Z")),
            1_767_323_045_000_000_123
        );
        assert_eq!(created_ns(&json!(1_767_323_045)), 1_767_323_045_000_000_000);
        assert_eq!(created_ns(&json!("bad")), 0);
    }

    #[test]
    fn ps_statuses() {
        let now = chrono::Utc::now().timestamp();
        assert_eq!(
            ps_status(&json!({"State": "running", "StartedAt": now - 120})),
            "Up 2 minutes"
        );
        assert_eq!(
            ps_status(&json!({"State": "exited", "ExitCode": 3, "ExitedAt": now - 30})),
            "Exited (3) 30 seconds ago"
        );
        assert_eq!(
            ps_status(&json!({"State": "exited", "ExitCode": 0})),
            "Exited (0)"
        );
        assert_eq!(ps_status(&json!({"State": "created"})), "Created");
        assert_eq!(
            ps_status(&json!({"State": "running", "StartedAt": now - 120, "Status": "healthy"})),
            "Up 2 minutes (healthy)"
        );
        assert_eq!(
            ps_status(&json!({"State": "running", "StartedAt": now, "Status": "starting"})),
            "Up Less than a second (starting)"
        );
        assert_eq!(
            ps_status(&json!({"State": "exited", "ExitCode": 1, "Status": "unhealthy"})),
            "Exited (1) (unhealthy)"
        );
        assert_eq!(ps_status(&json!({"State": "paused"})), "Paused");
        assert_eq!(ps_status(&json!({"State": "removing"})), "Removing");
    }

    #[test]
    fn the_server_version() {
        let s = velarx_proto::system::VersionRecord {
            version: "0.1.0".into(),
            built_ns: 1_767_323_045_000_000_000,
            os: "linux".into(),
            arch: "x86_64".into(),
            ..Default::default()
        };
        let v = server_version(&s);
        assert_eq!(v["APIVersion"], "5.8.9");
        assert_eq!(v["OsArch"], "linux/amd64");
        assert_eq!(v["Built"], 1767323045);
        assert_eq!(version(None)["Client"]["APIVersion"], API_VERSION);
        assert!(version(None).get("Server").is_none());
        let text = version_text(&json!({"Client": version(None)["Client"], "Server": v})).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "Client:       Podman Engine");
        assert!(lines[1].starts_with("Version:      "), "{text}");
        assert!(text.contains("\nGo Version:   rust\n"), "{text}");
        assert!(
            text.contains("\n\nServer:       Podman Engine\nVersion:      0.1.0\n"),
            "{text}"
        );
        assert!(!text.contains("Git Commit"), "{text}");
    }

    #[test]
    fn ports_of_a_container() {
        let c = json!({"NetworkSettings": {"Ports": {
            "8080/tcp": [{"HostIp": "", "HostPort": "9090"}],
            "53/udp": [{"HostIp": "127.0.0.1", "HostPort": "5353"}],
            "443/tcp": null
        }}});
        assert_eq!(
            port_lines(&c, None),
            ["53/udp -> 127.0.0.1:5353", "8080/tcp -> 0.0.0.0:9090"]
        );
        assert_eq!(port_lines(&c, Some("8080")), ["0.0.0.0:9090"]);
        assert_eq!(port_lines(&c, Some("53/udp")), ["127.0.0.1:5353"]);
        assert!(port_lines(&c, Some("1")).is_empty());
        assert!(port_lines(&json!({}), None).is_empty());
    }

    #[test]
    fn the_stats_of_a_container_are_podman_s() {
        let mut s = velarx_proto::workload::StatsRecord {
            name: "c1".into(),
            id: "0123456789abcdef0123".into(),
            cpu_percent: 1.5,
            cpu_nano: 2_200_000,
            cpu_system_nano: 2200,
            mem_usage: 585_728,
            mem_limit: 33_634_611_200,
            block_read: 4096,
            pids: 1,
            networks: vec![velarx_proto::workload::InterfaceStats {
                name: "eth0".into(),
                rx_bytes: 198,
                rx_packets: 3,
                tx_bytes: 472,
                tx_packets: 6,
                ..Default::default()
            }],
            ..Default::default()
        };
        let v = stats_fields(&s, 0.75, false);
        let r = |t: &str| template::Template::parse(t).unwrap().render(&v).unwrap();
        assert_eq!(
            r("{{.ID}} {{.Name}} {{.CPUPerc}} {{.AVGCPU}} {{.MemPerc}} {{.PIDS}}"),
            "0123456789ab c1 1.50% 0.75% 0.00% 1"
        );
        assert_eq!(r("{{.MemUsage}}"), "585.7kB / 33.63GB");
        assert_eq!(r("{{.MemUsageBytes}}"), "572KiB / 31.32GiB");
        assert_eq!(r("{{.NetIO}} {{.BlockIO}}"), "198B / 472B 4.096kB / 0B");
        assert_eq!(r("{{.UpTime}} {{.Up}} {{.CPUNano}}"), "2.2ms 2.2ms 2200000");
        assert_eq!(r("{{.ContainerID}}"), "0123456789abcdef0123");
        assert_eq!(r("{{.ContainerStats.MemUsage}}"), "585728");
        assert_eq!(r("{{(index .Network \"eth0\").TxBytes}}"), "472");
        assert_eq!(stats_fields(&s, 0.0, true)["ID"], "0123456789abcdef0123");
        let json = stats_json(&[v]).unwrap();
        assert!(json.starts_with("[\n {\n  \""), "{json}");
        let rows: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(rows[0]["mem_usage"], "585.7kB / 33.63GB");
        assert_eq!(rows[0]["cpu_time"], "2.2ms");
        assert_eq!(rows[0]["net_io"], "198B / 472B");
        // no limit: the memory of the host
        s.mem_limit = 0;
        assert!(stats_fields(&s, 0.0, false)["MemLimit"].as_u64().unwrap() > 0);
    }

    #[test]
    fn the_exposed_ports_of_ps_are_podman_s() {
        let published =
            json!([{"container_port": 80, "host_port": 8080, "range": 1, "protocol": "tcp"}]);
        let exposed = json!({"80": ["tcp"], "9000": ["tcp"], "9001": ["tcp"], "9002": ["tcp"],
                             "9004": ["tcp"], "53": ["udp", "tcp"]});
        assert_eq!(
            exposed_ports(&published, &exposed),
            ["53/tcp", "9000-9002/tcp", "9004/tcp", "53/udp"]
        );
        assert!(exposed_ports(&published, &Value::Null).is_empty());
    }

    #[test]
    fn sizes_as_go_units_prints_them() {
        assert_eq!(go_bytes_size(12_180_391.0), "11.62MiB");
        assert_eq!(go_bytes_size(1024.0), "1KiB");
        assert_eq!(go_bytes_size(0.0), "0B");
        assert_eq!(go_size(0.0), "0B");
        assert_eq!(go_size(999.0), "999B");
        assert_eq!(go_size(12_180_391.0), "12.18MB");
        assert_eq!(go_size(1_500.0), "1.5kB");
        assert_eq!(go_size(123_456.0), "123.5kB");
        assert_eq!(go_size_with(8_704_000.0, 3), "8.7MB");
        assert_eq!(go_size_with(123_456.0, 3), "123kB");
        assert_eq!(go_size_with(0.0, 3), "0B");
    }

    #[test]
    fn the_rows_of_system_df_are_podman_s() {
        let report = json!({
            "ImagesSize": 1000,
            "Images": [
                {"ImageID": "a", "UniqueSize": 400, "Containers": 1},
                {"ImageID": "a", "UniqueSize": 400, "Containers": 1},
                {"ImageID": "b", "UniqueSize": 600, "Containers": 0},
            ],
            "Containers": [
                {"Status": "running", "RWSize": 10},
                {"Status": "exited", "RWSize": 5},
            ],
            "Volumes": [{"Links": 2, "Size": 7, "ReclaimableSize": 0}],
        });
        let rows = df_summary(&report);
        let row = |i: usize| {
            let r = &rows[i];
            (
                r["Type"].as_str().unwrap().to_string(),
                r["Total"].as_i64().unwrap(),
                r["Active"].as_i64().unwrap(),
                r["Size"].as_str().unwrap().to_string(),
                r["Reclaimable"].as_str().unwrap().to_string(),
            )
        };
        assert_eq!(
            row(0),
            ("Images".into(), 3, 1, "1kB".into(), "600B (60%)".into())
        );
        assert_eq!(
            row(1),
            ("Containers".into(), 2, 1, "15B".into(), "5B (33%)".into())
        );
        assert_eq!(
            row(2),
            ("Local Volumes".into(), 1, 2, "7B".into(), "0B (0%)".into())
        );
    }

    #[test]
    fn a_template_sees_health_durations_as_go_prints_them() {
        let mut v = json!({"Config": {
            "Healthcheck": {"Interval": 6_000_000_000i64, "Retries": 3},
            "HealthcheckMaxLogCount": 5,
        }});
        durations_as_go(&mut v);
        let t = |f: &str| template::Template::parse(f).unwrap().render(&v).unwrap();
        assert_eq!(t("{{.Config.Healthcheck.Interval}}"), "6s");
        assert_eq!(t("{{.Config.Healthcheck.Retries}}"), "3");
        assert_eq!(t("{{.Config.HealthMaxLogCount}}"), "5");
        // (json shows what the JSON has: nanoseconds, the JSON names)
        assert_eq!(
            t("{{json .Config.Healthcheck}}"),
            r#"{"Interval":6000000000,"Retries":3}"#
        );
        assert!(!t("{{json .Config}}").contains("HealthMaxLogCount"));
    }

    #[test]
    fn info_is_podman_s_yaml() {
        let v = serde_json::json!({
            "host": {
                "arch": "amd64",
                "cgroupControllers": ["cpu", "memory"],
                "conmon": {"version": "conmon version 2.2.1, commit: "},
                "cpus": 24,
                "distribution": {"version": "44", "variant": ""},
                "idMappings": {"uidmap": [{"container_id": 0, "host_id": 1002, "size": 1}]},
                "ociRuntimes": [],
            },
            "plugins": {"authorization": null},
            "registries": {},
        });
        assert_eq!(
            go_yaml(&v),
            "host:
  arch: amd64
  cgroupControllers:
  - cpu
  - memory
  conmon:
    version: 'conmon version 2.2.1, commit: '
  cpus: 24
  distribution:
    variant: \"\"
    version: \"44\"
  idMappings:
    uidmap:
    - container_id: 0
      host_id: 1002
      size: 1
  ociRuntimes: []
plugins:
  authorization: null
registries: {}
"
        );
    }
}
