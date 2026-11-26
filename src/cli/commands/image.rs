// SPDX-License-Identifier: Apache-2.0
use super::*;

/// `push --format`: `oci`, the only one; podman's words for a format it
/// does not know, and the refusal of the Docker formats.
fn check_push_format(format: Option<&str>) -> anyhow::Result<()> {
    match format.filter(|f| !f.is_empty()) {
        None | Some("oci") => Ok(()),
        Some(f) => {
            velarx_base::docker::refuse_format_name(f).map_err(anyhow::Error::msg)?;
            anyhow::bail!("unknown format {f:?}. Choose on of the supported formats: 'oci'")
        }
    }
}

/// `inspect --latest`: with no container podman prints `[]` and says there
/// is nothing to inspect.
pub(super) fn inspect_latest(
    client: &client::EngineClient,
    latest: bool,
    named: Vec<String>,
    json: bool,
) -> anyhow::Result<Vec<String>> {
    match cli::run::named_or_latest(client, latest, named) {
        Err(e) if latest && e.to_string() == "no such container" => {
            if json {
                println!("[]");
            }
            anyhow::bail!("no containers to inspect: no such container")
        }
        r => r,
    }
}

fn write_file(path: &std::path::Path, content: &str) -> anyhow::Result<()> {
    std::fs::write(path, content).map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))
}

/// What `--metadata-file` writes (buildx's keys): the digest of the
/// manifest, the digest of the configuration and the descriptor of the
/// manifest.
fn build_metadata(image: &velarx_proto::workload::ImageRecord) -> serde_json::Value {
    serde_json::json!({
        "containerimage.digest": image.digest,
        "containerimage.config.digest": velarx_shape::id_with_algorithm(&image.id),
        "containerimage.descriptor": {
            "mediaType": image.manifest_type,
            "digest": image.digest,
            "size": image.manifest_size,
        },
    })
}

pub(super) fn image_id_of(client: &client::EngineClient, name: &str) -> anyhow::Result<String> {
    // (a manifest list is no image: its id is what the build gives)
    match client.inspect_image(name) {
        Ok(image) => Ok(image.id),
        Err(e) if e.is_not_found() => Ok(name.to_string()),
        Err(e) => Err(e.into()),
    }
}

/// Print pull statistics (used for non-TTY mode)
pub(super) fn print_pull_stats(stats: Option<velarx_proto::workload::TransferStats>) {
    use velarx_proto::workload::SOURCE_STORE;
    let Some(stats) = stats else {
        return;
    };
    let total_bytes: u64 = stats.by_source.iter().map(|s| s.bytes).sum();
    let total_files: u64 = stats.by_source.iter().map(|s| s.files).sum();
    if total_bytes == 0 && total_files == 0 {
        return;
    }
    eprintln!();
    eprintln!("Pull Statistics:");
    if stats.layers_cached > 0 {
        eprintln!("  Layers cached (skipped):    {}", stats.layers_cached);
    }
    for source in &stats.by_source {
        let label = if source.name == SOURCE_STORE {
            "Deduplicated (from store)".to_string()
        } else {
            format!("From {}", source.name)
        };
        eprintln!(
            "  {:<27} {} files, {}",
            format!("{label}:"),
            source.files,
            format_size(source.bytes)
        );
    }
    if total_bytes > 0 {
        let percents: Vec<String> = stats
            .by_source
            .iter()
            .map(|s| {
                let what = if s.name == SOURCE_STORE {
                    "deduplicated"
                } else {
                    s.name.as_str()
                };
                format!(
                    "{:.1}% {what}",
                    (s.bytes as f64 / total_bytes as f64) * 100.0
                )
            })
            .collect();
        eprintln!();
        eprintln!(
            "  Total: {} ({})",
            format_size(total_bytes),
            percents.join(", ")
        );
    }
    if stats.duration_ms > 0 {
        let duration_secs = stats.duration_ms as f64 / 1000.0;
        // (what came over the wire, from whichever source)
        let fetched: u64 = stats
            .by_source
            .iter()
            .filter(|s| s.name != velarx_proto::workload::SOURCE_STORE)
            .map(|s| s.bytes)
            .sum();
        let throughput = if fetched > 0 {
            format!(
                " ({:.1} MB/s)",
                (fetched as f64 / 1_000_000.0) / duration_secs
            )
        } else {
            String::new()
        };
        eprintln!(
            "  Time: {}{}",
            format_duration(stats.duration_ms),
            throughput
        );
    }
}

/// Write the archive of `images` to a file, a directory (oci-dir) or the
/// standard output.
pub(super) fn image_save(
    client: &client::EngineClient,
    images: &[String],
    format: &str,
    output: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use std::io::IsTerminal;
    if images.is_empty() {
        anyhow::bail!("no image to save");
    }
    let location = |path: &std::path::Path| {
        let path = path.to_string_lossy().into_owned();
        match format {
            "oci-dir" => Ok(ImageLocation::OciLayout { path, tag: None }),
            "docker-archive" | "oci-archive" => Ok(ImageLocation::OciArchive { path, tag: None }),
            other => Err(anyhow::anyhow!("unknown archive format `{other}`")),
        }
    };
    match output {
        Some(path) => {
            if format == "oci-dir" && std::fs::read_dir(path).is_ok_and(|mut d| d.next().is_some())
            {
                anyhow::bail!("`{}` is not empty", path.display());
            }
            // (opened here: the engine writes beneath it and nothing else; an
            // archive replaces its file when it is whole)
            let opened = cli::transport::open_destination(&location(path)?, false)?
                .ok_or_else(|| anyhow::anyhow!("`{}` is no destination", path.display()))?;
            client.save_images(images, format, &opened.fd)?;
            opened.finish()?;
        }
        None => {
            if format == "oci-dir" {
                anyhow::bail!("oci-dir needs --output");
            }
            if std::io::stdout().is_terminal() {
                anyhow::bail!("refusing to write the archive to a terminal, use --output");
            }
            let stdout = std::io::stdout().lock();
            let fd = rustix::io::dup(&stdout)?;
            if let Err(e) = client.save_images(images, format, &fd) {
                // A reader that went away (`| head`) ends the command quietly
                // with the status of SIGPIPE, as podman's ends: the write end
                // of a pipe nobody reads says so (`POLLERR`).
                if no_reader(&fd) {
                    return Err(client::ClientError::Interrupted(libc::SIGPIPE).into());
                }
                return Err(e.into());
            }
        }
    }
    Ok(())
}

/// Whether the pipe `fd` (open for writing) has no reader any more.
fn no_reader(fd: &std::os::fd::OwnedFd) -> bool {
    use rustix::event::{poll, PollFd, PollFlags};
    let mut fds = [PollFd::new(fd, PollFlags::OUT)];
    poll(&mut fds, Some(&rustix::event::Timespec::default()))
        .is_ok_and(|n| n > 0 && fds[0].revents().contains(PollFlags::ERR))
}

/// Write what `stream` has to the standard output.  A reader that went
/// away (`| head`) ends the command quietly with the status of SIGPIPE, as
/// podman's ends.
pub(crate) fn to_stdout(stream: &mut dyn std::io::Read, what: &str) -> anyhow::Result<()> {
    match std::io::copy(stream, &mut std::io::stdout().lock()) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
            Err(client::ClientError::Interrupted(libc::SIGPIPE).into())
        }
        Err(e) => Err(anyhow::anyhow!("{what}: {e}")),
    }
}

/// Load an archive from a file, a directory (an OCI layout) or standard
/// input: the engine pulls it from the descriptor the command opens, as from
/// any origin.
pub(super) fn image_load(
    client: &client::EngineClient,
    input: Option<&std::path::Path>,
    platform: Option<&str>,
    quiet: bool,
) -> anyhow::Result<Vec<velarx_proto::workload::PulledImage>> {
    use std::io::IsTerminal;
    let mut shown = shown_unless(quiet);
    let source = match input {
        Some(path) => cli::transport::open_source("archive:", path, path.is_dir())
            .map_err(|e| anyhow::anyhow!("cannot open `{}`: {e}", path.display()))?,
        None => {
            if std::io::stdin().is_terminal() {
                anyhow::bail!("no archive on standard input, use --input");
            }
            cli::transport::open_source("archive:", std::path::Path::new("/dev/stdin"), false)?
        }
    };
    let loaded = source.pull(client, "archive:", platform, Some(&mut |p| shown.event(p)));
    shown.finish();
    Ok(loaded?)
}

/// The progress of a command, unless it is quiet.
pub(super) fn shown_unless(quiet: bool) -> Renderer {
    if quiet {
        Renderer::silent()
    } else {
        Renderer::new()
    }
}

/// Pull the image of a command that is about something else (`run`, `create`)
/// with the progress bars on the standard error, nothing on the standard
/// output.
pub fn pull_showing_progress(
    client: &client::EngineClient,
    image: &str,
    ask: &client::PullOptions<'_>,
    quiet: bool,
) -> client::ClientResult<()> {
    // (bars on a terminal; elsewhere and with -q only the warnings)
    let mut shown = if quiet || !progress::on_terminal() {
        Renderer::silent()
    } else {
        Renderer::new()
    };
    stream_pull(client, image, ask, &mut shown).map(|_| ())
}

/// podman's question before a prune, after `warning`: whether the answer
/// is yes; the end of the input is an error, as podman's `EOF`.
pub(super) fn confirm_prune(warning: &str) -> anyhow::Result<bool> {
    use std::io::Write;
    print!("{warning}\nAre you sure you want to continue? [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer)? == 0 {
        anyhow::bail!("EOF");
    }
    Ok(answer.to_lowercase().starts_with('y'))
}

/// Pull `image`, its progress shown by `renderer`.
pub(super) fn stream_pull(
    client: &client::EngineClient,
    image: &str,
    ask: &client::PullOptions<'_>,
    renderer: &mut Renderer,
) -> client::ClientResult<client::PullResponse> {
    let result = client.pull_image_progress(image, ask, &mut |p| renderer.event(p));
    renderer.finish();
    result
}

/// What `search` prints of `hits`, as podman: a table of the names and the
/// descriptions (cut at 44 bytes unless `no_trunc`; the stars, official
/// and automated columns too with `compatible`), of the names and the tags
/// with `list_tags`, else `format` (`json`: the tags of each name with
/// `list_tags`).
pub(super) fn search_report(
    hits: &[client::SearchHit],
    format: Option<&str>,
    list_tags: bool,
    no_trunc: bool,
    compatible: bool,
) -> anyhow::Result<String> {
    let json = format == Some("json");
    if json && list_tags {
        let mut names: Vec<(String, Vec<String>)> = Vec::new();
        for h in hits {
            match names.iter_mut().find(|(n, _)| *n == h.name) {
                Some((_, tags)) => tags.push(h.tag.clone()),
                None => names.push((h.name.clone(), vec![h.tag.clone()])),
            }
        }
        let list: Vec<serde_json::Value> = names
            .into_iter()
            .map(|(name, tags)| serde_json::json!({"Name": name, "Tags": tags}))
            .collect();
        return Ok(format!("{}\n", serde_json::to_string_pretty(&list)?));
    }
    let ok = |b: bool| if b { "[OK]" } else { "" };
    let rows: Vec<serde_json::Value> = hits
        .iter()
        .map(|h| {
            let mut d = h.description.replace('\n', " ");
            if d.len() > 44 && !no_trunc && !json {
                let mut cut = 44;
                while !d.is_char_boundary(cut) {
                    cut -= 1;
                }
                d = format!("{}...", d[..cut].trim());
            }
            serde_json::json!({
                "Index": h.index,
                "Name": h.name,
                "Description": d,
                "Stars": h.stars,
                "Official": ok(h.official),
                "Automated": ok(h.automated),
                "Tag": h.tag,
            })
        })
        .collect();
    if rows.is_empty() {
        return Ok(String::new());
    }
    if json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(&rows)?));
    }
    let default = if list_tags {
        "table {{.Name}}\t{{.Tag}}"
    } else if compatible {
        "table {{.Name}}\t{{.Description}}\t{{.Stars}}\t{{.Official}}\t{{.Automated}}"
    } else {
        "table {{.Name}}\t{{.Description}}"
    };
    cli::template::format_list(format.unwrap_or(default), &rows, &Default::default())
        .map_err(anyhow::Error::msg)
}

/// `image pulls`: the pulls in progress as a table, ids, or a template.
pub(super) fn pulls_report(
    pulls: &[velarx_proto::workload::PullListed],
    format: Option<&str>,
    quiet: bool,
    no_trunc: bool,
) -> anyhow::Result<String> {
    let shown = |id: &str| -> String {
        if no_trunc {
            id.to_string()
        } else {
            id.chars().take(12).collect()
        }
    };
    if quiet {
        return Ok(pulls
            .iter()
            .map(|p| format!("{}\n", shown(&p.id)))
            .collect());
    }
    let rows: Vec<serde_json::Value> = pulls
        .iter()
        .map(|p| {
            let progress = match p.bytes_total {
                0 => format!("{}%", p.percent),
                total => format!(
                    "{}% {}/{}",
                    p.percent,
                    cli::report::go_size(p.bytes_done as f64),
                    cli::report::go_size(total as f64)
                ),
            };
            serde_json::json!({
                "ID": shown(&p.id),
                "Names": p.names.join(","),
                "State": p.state.word(),
                "Progress": progress,
                "Percent": p.percent,
                "BytesDone": p.bytes_done,
                "BytesTotal": p.bytes_total,
                "LayersDone": p.layers_done,
                "LayersTotal": p.layers_total,
                "Containers": p.containers,
                "Error": p.error,
                "StartedAt": p.started_at,
            })
        })
        .collect();
    if rows.is_empty() && format.is_none() {
        return Ok(String::new());
    }
    let default =
        "table {{.ID}}\t{{.Names}}\t{{.State}}\t{{.Progress}}\t{{.Containers}}\t{{.Error}}";
    cli::template::format_list(format.unwrap_or(default), &rows, &Default::default())
        .map_err(anyhow::Error::msg)
}

/// `pull --all-tags`: the tags of the repository of `image` (its own tag, if
/// any, is not looked at), each pulled as `pull` of that name.
fn pull_all_tags(cmd: ImageCommands, inv: &Invocation<'_>) -> anyhow::Result<()> {
    let ImageCommands::Pull {
        image,
        tls_verify,
        access,
        ..
    } = &cmd
    else {
        unreachable!("pull_all_tags is for pull");
    };
    let [image] = image.as_slice() else {
        unreachable!("pull of several images pulls each");
    };
    if image.contains('@') {
        anyhow::bail!("tag can't be used with --all-tags/-a");
    }
    // (a colon after the last slash is a tag, else a port)
    let repo = match image.rsplit_once(':') {
        Some((repo, tag)) if !tag.contains('/') => repo,
        _ => image.as_str(),
    };
    let tags = {
        let client = get_client(inv)?;
        let access = registry_access(&client, access, repo, false)?;
        client.search_images(&client::SearchRequest {
            term: repo.to_string(),
            list_tags: true,
            tls_verify: Some(*tls_verify),
            access,
            ..Default::default()
        })?
    };
    if tags.is_empty() {
        anyhow::bail!("no tags found for {repo}");
    }
    for hit in tags {
        let mut one = cmd.clone();
        if let ImageCommands::Pull {
            image, all_tags, ..
        } = &mut one
        {
            *image = vec![format!("{}:{}", hit.name, hit.tag)];
            *all_tags = false;
        }
        run_image_command(one, inv)?;
    }
    Ok(())
}

/// The settings of `commit --config` as podman decodes them (a Docker
/// `Schema2Config`, Go's words for a field of the wrong type): a command or
/// entrypoint may be one string.
fn schema2_config(mut v: serde_json::Value) -> Result<serde_json::Value, String> {
    use serde_json::Value;
    fn kind(v: &Value) -> &'static str {
        match v {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }
    let Value::Object(fields) = &mut v else {
        return Err(format!(
            "json: cannot unmarshal {} into Go value of type manifest.Schema2Config",
            kind(&v)
        ));
    };
    let strings = |v: &Value| v.as_array().is_some_and(|a| a.iter().all(Value::is_string));
    for (name, value) in fields.iter_mut() {
        let (fits, go) = match name.as_str() {
            "User" | "WorkingDir" | "StopSignal" => (value.is_string(), "string"),
            "Env" => (strings(value), "[]string"),
            "Cmd" | "Entrypoint" => {
                if let Value::String(s) = value {
                    *value = Value::Array(vec![Value::String(std::mem::take(s))]);
                }
                (strings(value), "strslice.StrSlice")
            }
            "Labels" => (
                value
                    .as_object()
                    .is_some_and(|m| m.values().all(Value::is_string)),
                "map[string]string",
            ),
            "ExposedPorts" | "Volumes" => (value.is_object(), "map[string]struct {}"),
            _ => continue,
        };
        if !fits && !value.is_null() {
            return Err(format!(
                "json: cannot unmarshal {} into Go struct field Schema2Config.{name} of type {go}",
                kind(value)
            ));
        }
    }
    Ok(v)
}

/// The output of a build split by platform: `FILE_OS_ARCH` for each, which
/// the standard output and error of the command go to from the moment the
/// build for the platform starts.
struct LogSplit(std::path::PathBuf);

impl LogSplit {
    fn switch(&self, platform: &str) -> anyhow::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut parts = platform.split('/');
        let (os, arch) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        let mut name = self.0.clone().into_os_string();
        name.push(format!("_{os}_{arch}"));
        let path = std::path::PathBuf::from(name);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| {
                anyhow::anyhow!("opening logfile: {:?}: {e}", path.display().to_string())
            })?;
        let _ = std::io::stdout().flush();
        rustix::stdio::dup2_stdout(&file)?;
        rustix::stdio::dup2_stderr(&file)?;
        Ok(())
    }
}

pub(super) fn run_image_command(cmd: ImageCommands, inv: &Invocation<'_>) -> anyhow::Result<()> {
    // podman pulls the images one after the other: a failure is said and
    // the next goes on, the last failure is the error of the command
    // (a signal ends it at once)
    if let ImageCommands::Pull { image, .. } = &cmd {
        if image.len() > 1 {
            let mut last: Option<anyhow::Error> = None;
            for each in image {
                let mut one = cmd.clone();
                if let ImageCommands::Pull { image, .. } = &mut one {
                    *image = vec![each.clone()];
                }
                if let Err(e) = run_image_command(one, inv) {
                    if e.downcast_ref::<client::ClientError>()
                        .is_some_and(client::ClientError::is_interrupted)
                    {
                        return Err(e);
                    }
                    if let Some(earlier) = last.replace(e) {
                        eprintln!("Error: {earlier:#}");
                    }
                }
            }
            return last.map_or(Ok(()), Err);
        }
    }
    if matches!(cmd, ImageCommands::Pull { all_tags: true, .. }) {
        return pull_all_tags(cmd, inv);
    }
    let client = get_client(inv)?;

    match cmd {
        ImageCommands::Pull {
            platform,
            os,
            arch,
            variant,
            policy,
            retry,
            retry_delay,
            all_tags,
            quiet,
            decryption_key,
            disable_content_trust: _,
            lazy,
            sources,
            tls_verify,
            access,
            image,
        } => {
            debug_assert!(!all_tags, "pull_all_tags took it");
            let [image] = <[String; 1]>::try_from(image)
                .unwrap_or_else(|_| unreachable!("pull of several images pulls each"));
            if !decryption_key.is_empty() {
                anyhow::bail!("--decryption-key is not supported: velarx pulls no encrypted image");
            }
            let platform =
                cli::platform_of(platform, os, arch, variant).map_err(anyhow::Error::msg)?;
            let retry = client::policy::retry_of(retry, retry_delay.as_deref())
                .map_err(anyhow::Error::msg)?;
            let image = match cli::transport::pull(&client, &image, platform.as_deref())? {
                cli::transport::Source::Name(name) => name,
                cli::transport::Source::Local(name) => {
                    match client.inspect_image(&name) {
                        Ok(image) => println!("{}", image.id),
                        Err(e) if e.is_not_found() => anyhow::bail!("{name}: image not known"),
                        Err(e) => return Err(e.into()),
                    }
                    return Ok(());
                }
                cli::transport::Source::Imported(images) => {
                    for image in images {
                        println!("{}", image_id_of(&client, &image.id)?);
                    }
                    return Ok(());
                }
            };
            let access = registry_access(&client, &access, &image, false)?;
            let ask = client::PullOptions {
                tls_verify,
                platform: platform.as_deref(),
                access: &access,
                retry,
                sources: sources.as_deref(),
            };
            if policy != cli::PullPolicy::Always {
                let present = match client.inspect_image(&image) {
                    Ok(found) => Some(found.id),
                    Err(e) if e.is_not_found() => None,
                    Err(e) => return Err(e.into()),
                }
                .filter(|_| {
                    policy != cli::PullPolicy::Newer
                        || !client::policy::newer_in_registry(&client, &image, &ask)
                });
                if policy == cli::PullPolicy::Never && present.is_none() {
                    anyhow::bail!("{image}: image not known");
                }
                if let Some(id) = present {
                    println!("{id}");
                    return Ok(());
                }
            }
            if quiet && !lazy {
                // (streamed for its warnings, which podman shows with -q)
                let id = stream_pull(&client, &image, &ask, &mut Renderer::silent())?.id;
                println!("{id}");
            } else if lazy {
                println!("Lazy pulling {} (metadata only)...", image);
                let result = client.pull_image_lazy(&image, &ask)?;
                println!("Pulled (lazy): {}", result.id);
                println!("  Files will be fetched on-demand when accessed");
            } else {
                // bars on a terminal, lines elsewhere
                let terminal = progress::on_terminal();
                eprintln!("Trying to pull {image}...");
                let done = stream_pull(&client, &image, &ask, &mut Renderer::on(terminal))?;
                let (id, stats) = (done.id, done.stats);
                print_pull_stats(stats);
                println!("{id}");
            }
        }
        ImageCommands::List { all, out, args } => cli::report::images(&client, all, &out, &args)?,
        ImageCommands::Remove {
            force,
            all,
            ignore,
            no_prune: _,
            images,
        } => {
            if all {
                if !images.is_empty() {
                    anyhow::bail!(
                        "when using the --all switch, you may not pass any images names or IDs"
                    );
                }
                let r = client.remove_all_images(force, ignore)?;
                for w in r.warnings {
                    client::warn(&w);
                }
                for n in r.untagged {
                    println!("Untagged: {n}");
                }
                for d in r.deleted {
                    println!("Deleted: {d}");
                }
                match r.errors.as_slice() {
                    [] => {}
                    [e] => eprintln!("Error: {e}"),
                    many => eprintln!(
                        "Error: {} errors occurred:\n\t* {}",
                        many.len(),
                        many.join("\n\t* ")
                    ),
                }
                if r.exit_code != 0 {
                    exit_with(r.exit_code);
                }
                return Ok(());
            }
            if images.is_empty() {
                anyhow::bail!("image name or ID must be specified");
            }
            let mut errors: Vec<String> = Vec::new();
            let mut refused = false;
            let mut in_use = false;
            let ended = cli::run::each_item(
                images,
                |image| match client.remove_image(image, force) {
                    Err(e) if (ignore || force) && e.is_not_found() => Ok(()),
                    Ok(r) => {
                        for w in r.warnings {
                            client::warn(&w);
                        }
                        for n in r.untagged {
                            println!("Untagged: {n}");
                        }
                        for d in r.deleted {
                            println!("Deleted: {d}");
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                },
                |_, e| {
                    refused |= cli::report::refused_image(&e);
                    in_use |= e.is_conflict();
                    errors.push(e.to_string());
                },
            );
            if let Err(e) = ended {
                for e in &errors {
                    eprintln!("Error: {e}");
                }
                return Err(e);
            }
            // (as podman: the one error, or go-multierror's list; 125 for a
            // reference it refuses, 2 for an image in use, else 1)
            match errors.as_slice() {
                [] => {}
                [e] => {
                    eprintln!("Error: {e}");
                    exit_with(if refused {
                        125
                    } else if in_use {
                        2
                    } else {
                        1
                    });
                }
                many => {
                    eprintln!(
                        "Error: {} errors occurred:\n\t* {}",
                        many.len(),
                        many.join("\n\t* ")
                    );
                    exit_with(if refused {
                        125
                    } else if in_use {
                        2
                    } else {
                        1
                    });
                }
            }
        }
        ImageCommands::Exists { image } => {
            exit_with(if client.exists(client::Kind::Image, &image)? {
                0
            } else {
                1
            })
        }
        ImageCommands::History { human, out, image } => {
            cli::report::history(&client, &image, &out, human)?
        }
        ImageCommands::Inspect { format, images } => {
            inspect_as_podman(&client, client::Kind::Image, &images, format.as_deref())?
        }
        ImageCommands::Untag { image, names } => {
            client.untag_image(&image, &names)?;
        }
        ImageCommands::Tag { source, targets } => {
            for target in targets {
                client.tag_image(&source, &target)?;
            }
        }
        ImageCommands::Push {
            image,
            destination,
            all_tags,
            compression_format,
            compression_level,
            force_compression: _,
            compress,
            sinks,
            format,
            digestfile,
            retry,
            retry_delay,
            remove_signatures: _,
            disable_content_trust: _,
            encrypt_layer,
            encryption_key,
            signing,
            tls_verify,
            access,
            quiet,
        } => {
            if !encryption_key.is_empty() || !encrypt_layer.is_empty() {
                anyhow::bail!(
                    "--encryption-key and --encrypt-layer are not supported: velarx pushes no encrypted image"
                );
            }
            let sign = signing.spec("push")?;
            if signing.sign_by.is_some() && all_tags {
                anyhow::bail!("--sign-by is not supported with --all-tags");
            }
            let retry = client::policy::retry_of(retry, retry_delay.as_deref())
                .map_err(anyhow::Error::msg)?;
            let image = ImageLocation::local(&image, "push (the image to push)")?;
            check_push_format(format.as_deref())?;
            // (a path is opened here, by the client: the engine and the
            // pusher never resolve what the user typed)
            let mut external = false;
            let (destination, opened) = match destination {
                // (a scheme of `[[transports]]`: the engine finds its
                // pusher, the text goes as it is)
                Some(d) if ImageLocation::external(&d)?.is_some() => {
                    if compress {
                        anyhow::bail!("--compress is for the destinations of the dir: transport")
                    }
                    external = true;
                    (Some(d), None)
                }
                Some(d) => {
                    let location = ImageLocation::parse(&d)?;
                    match cli::transport::open_destination(&location, compress)? {
                        Some(opened) => (Some(d), Some(opened)),
                        None => (cli::transport::registry_destination(&location)?, None),
                    }
                }
                None if compress => {
                    anyhow::bail!("--compress is for the destinations of the dir: transport")
                }
                None => (None, None),
            };
            let to_path = opened.is_some();
            // (where the signature goes is known before anything is pushed)
            let gpg = match &signing.sign_by {
                Some(_) if to_path || external => {
                    anyhow::bail!("--sign-by is for the images of a registry")
                }
                Some(key) => Some((
                    key,
                    cli::gpg::Target::new(destination.as_deref().unwrap_or(&image), None)?,
                )),
                None => None,
            };
            // (`dir: --compress` is `--compression-format gzip` of that destination)
            let compression_format = match (&opened, compress) {
                (Some(_), true) => Some("gzip".to_string()),
                _ => compression_format,
            };
            let target = destination.as_deref().unwrap_or(&image);
            let access = if opened.is_some() {
                Default::default()
            } else {
                registry_access(&client, &access, target, true)?
            };
            let request = client::PushImageRequest {
                destination: destination.clone(),
                compression_format,
                compression_level,
                tls_verify,
                access,
                retry,
                sign,
                sinks,
                destination_fd: opened.as_ref().map(|o| o.fd.clone()),
            };
            // (asked for with --digest, or inherited from the image: said once;
            // a sha256 manifest over sha512 layers has sha512 blobs too)
            if !to_path
                && client.inspect_image(&image).is_ok_and(|i| {
                    std::iter::once(&i.digest)
                        .chain(&i.layers)
                        .any(|d| d.starts_with("sha512:"))
                })
            {
                eprintln!("{}", cli::SHA512_PUSH_WARNING);
            }
            if all_tags {
                if opened.is_some() {
                    anyhow::bail!("--all-tags is for the images of a registry");
                }
                if digestfile.is_some() {
                    anyhow::bail!(
                        "--digestfile names the digest of one image: not with --all-tags"
                    );
                }
                let mut shown = shown_unless(quiet);
                let pushed = client.push_image_all_tags(&image, &request, &mut |p| shown.event(p));
                shown.finish();
                let pushed = pushed?;
                if !quiet {
                    eprintln!("Pushed all tags for: {}", image);
                    for (tag, digest) in pushed {
                        eprintln!("  {tag}: {digest}");
                    }
                }
            } else {
                let mut shown = shown_unless(quiet);
                let result = client.push_image(&image, &request, &mut |p| shown.event(p));
                shown.finish();
                let result = result?;
                if let Some(opened) = opened {
                    opened.finish()?;
                }
                if let Some(path) = digestfile {
                    std::fs::write(&path, &result.digest)
                        .map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))?;
                }
                if let Some((key, target)) = gpg {
                    target.sign(key, signing.sign_passphrase_file.as_deref(), &result.digest)?;
                }
                if !quiet {
                    eprintln!("Pushed: {}", destination.as_deref().unwrap_or(&image));
                    eprintln!("Digest: {}", result.digest);
                    eprintln!(
                        "Blobs: {} uploaded, {} mounted, {} already there",
                        result.blobs_uploaded, result.blobs_mounted, result.blobs_existing
                    );
                }
                // (a sha512 manifest pushed by a tag is put by its digest too: said
                // when the registry refuses it, even with --quiet)
                if result.digest.starts_with("sha512:") && !to_path {
                    if let Some(name) = cli::pushed_by_digest_name(
                        destination.as_deref().unwrap_or(&image),
                        &result.digest,
                    ) {
                        let refusals = cli::refusal_warnings(&result.placed, &name);
                        if refusals.is_empty() && !quiet {
                            eprintln!("Pushed: {name}");
                        }
                        for line in refusals {
                            eprintln!("{line}");
                        }
                    }
                }
            }
        }
        ImageCommands::Search {
            filter,
            format,
            limit,
            list_tags,
            no_trunc,
            compatible,
            tls_verify,
            access,
            term,
        } => {
            if list_tags && !filter.is_empty() {
                anyhow::bail!("filters are not applicable to list tags result");
            }
            let access = registry_access(&client, &access, "", false)?;
            let hits = client.search_images(&client::SearchRequest {
                term,
                limit: limit.and_then(|l| u32::try_from(l).ok()).unwrap_or(0),
                filters: filter,
                list_tags,
                tls_verify,
                access,
            })?;
            print!(
                "{}",
                search_report(&hits, format.as_deref(), list_tags, no_trunc, compatible)?
            );
        }
        ImageCommands::Sign {
            sign_by,
            directory,
            passphrase_file,
            tls_verify,
            access,
            images,
        } => {
            for image in images {
                // (the name signed is the one asked of the registry: a short
                // name is not resolved to another registry)
                let target = cli::gpg::Target::new(&image, directory.as_deref())?;
                let image = target.name();
                let access = registry_access(&client, &access, &image, false)?;
                let digest = client
                    .remote_digest(&image, tls_verify, None, &access)?
                    .remote;
                target.sign(&sign_by, passphrase_file.as_deref(), &digest)?;
                println!("Signed {image} ({digest})");
            }
        }
        ImageCommands::Trust(_) => unreachable!("image trust edits files and is run before"),
        ImageCommands::GenerateSigstoreKey { .. } => {
            unreachable!("image generate-sigstore-key writes files and is run before")
        }
        ImageCommands::Tree {
            whatrequires,
            image,
        } => print!("{}", client.image_tree(&image, whatrequires)?),
        ImageCommands::Pulls {
            quiet,
            no_trunc,
            format,
            cancel,
        } => {
            for id in &cancel {
                client.remove_image(id, false)?;
                println!("{id}");
            }
            if cancel.is_empty() {
                let pulls = client.image_pulls()?;
                print!(
                    "{}",
                    pulls_report(&pulls, format.as_deref(), quiet, no_trunc)?
                );
            }
        }
        ImageCommands::Complete { access, image } => {
            let access = complete_access(&client, &access, &image)?;
            let stats = client.complete_image(&image, &access)?;
            println!(
                "Completed {}: {} fetched from the registry, {} already there",
                image,
                stats.from(velarx_proto::workload::SOURCE_REGISTRY).0,
                stats.from(velarx_proto::workload::SOURCE_STORE).0
            );
        }
        ImageCommands::Save {
            output,
            format,
            images,
            quiet: _,
            multi_image_archive: _,
            compress,
            uncompressed: _,
        } => {
            if compress {
                anyhow::bail!("--compress can only be set when --format is 'docker-dir'");
            }
            image_save(&client, &images, &format, output.as_deref())?
        }
        ImageCommands::Load {
            input,
            quiet,
            platform,
        } => {
            let loaded = image_load(&client, input.as_deref(), platform.as_deref(), quiet)?;
            for image in loaded {
                if quiet {
                    println!("{}", short_id(&image.id));
                } else if image.names.is_empty() {
                    println!("Loaded image: {}", short_id(&image.id));
                } else {
                    for name in &image.names {
                        println!("Loaded image: {name}");
                    }
                }
            }
        }
        ImageCommands::Import {
            change,
            message,
            file,
            name,
            quiet,
            arch,
            os,
            variant,
            digest,
        } => {
            use std::io::IsTerminal;
            cli::check_digest_flag(digest.as_deref()).map_err(anyhow::Error::msg)?;
            let platform = cli::platform_of(None, os, arch, variant).map_err(anyhow::Error::msg)?;
            let mut shown = shown_unless(quiet);
            let id = if file == "-" {
                if std::io::stdin().is_terminal() {
                    anyhow::bail!("no archive on standard input");
                }
                client.import_image(
                    name.as_deref(),
                    &change,
                    message.as_deref(),
                    platform.as_deref(),
                    digest.as_deref(),
                    Box::new(|w| {
                        let mut stdin = Transfer::new(
                            std::io::stdin().lock(),
                            &mut shown,
                            "archive",
                            "importing",
                            0,
                        );
                        std::io::copy(&mut stdin, w)?;
                        stdin.finish();
                        Ok(())
                    }),
                )
            } else {
                let mut f = std::fs::File::open(&file)
                    .map_err(|e| anyhow::anyhow!("cannot open `{file}`: {e}"))?;
                let size = f.metadata().map(|m| m.len()).unwrap_or(0);
                client.import_image(
                    name.as_deref(),
                    &change,
                    message.as_deref(),
                    platform.as_deref(),
                    digest.as_deref(),
                    Box::new(|w| {
                        let mut f = Transfer::new(&mut f, &mut shown, "archive", "importing", size);
                        std::io::copy(&mut f, w)?;
                        f.finish();
                        Ok(())
                    }),
                )
            };
            shown.finish();
            println!("{}", velarx_shape::id_with_algorithm(&id?));
        }
        ImageCommands::Commit {
            author,
            message,
            change,
            config,
            pause,
            format,
            digest,
            include_volumes,
            squash,
            iidfile,
            quiet,
            container,
            image,
        } => {
            velarx_base::docker::refuse_format_name(&format).map_err(anyhow::Error::msg)?;
            cli::check_digest_flag(digest.as_deref()).map_err(anyhow::Error::msg)?;
            if format != "oci" {
                anyhow::bail!("unrecognized image format {format:?}");
            }
            // (podman reads a Schema2Config; an empty file is no settings)
            let override_config = match config {
                Some(path) => {
                    let text = std::fs::read_to_string(&path).map_err(|e| {
                        anyhow::anyhow!(
                            "--config: open {}: {}",
                            path.display(),
                            super::pod::io_text(&e)
                        )
                    })?;
                    match text.trim() {
                        "" => None,
                        t => Some(
                            serde_json::from_str::<serde_json::Value>(t)
                                .map_err(|e| anyhow::anyhow!("--config: {e}"))
                                .and_then(|v| schema2_config(v).map_err(anyhow::Error::msg))?,
                        ),
                    }
                }
                None => None,
            };
            let req = client::CommitContainerRequest {
                container,
                image,
                author,
                message,
                changes: change,
                pause,
                digest,
                include_volumes,
                squash,
                override_config,
            };
            let mut shown = shown_unless(quiet);
            let result = client.commit_container(&req, &mut |p| shown.event(p));
            shown.finish();
            let id = result?;
            if let Some(path) = iidfile {
                let digest = client.inspect_image(&id)?.digest;
                std::fs::write(&path, digest)
                    .map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))?;
            }
            if !quiet {
                eprintln!("Writing manifest to image destination");
            }
            println!("{id}");
        }
        ImageCommands::Diff { format, image } => {
            print_changes(&client.image_changes(&image)?, format.as_deref())?
        }
        ImageCommands::Prune {
            all,
            filter,
            force,
            build_cache,
            external: _,
        } => {
            if !force
                && !confirm_prune(if all {
                    "WARNING! This command removes all images without at least one container associated with them."
                } else {
                    "WARNING! This command removes all dangling images."
                })?
            {
                return Ok(());
            }
            let pruned = client.prune_images(all, &filter)?;
            for img in &pruned {
                println!("Deleted: {}", img.id);
            }
            let mut space = pruned.iter().fold(0u64, |n, p| n.saturating_add(p.size));
            // podman's --build-cache: the directories of RUN
            // --mount=type=cache go too
            if build_cache {
                space = space.saturating_add(client.prune_build_cache()?);
            }
            println!("Total reclaimed space: {}", format_bytes(space));
        }
        ImageCommands::Build {
            tag,
            file,
            build_arg,
            label,
            no_cache,
            layers,
            rm,
            force_rm: _,
            target,
            platform,
            os,
            arch,
            variant,
            ignorefile,
            extra,
            unsupported,
            manifest,
            all_platforms,
            squash,
            squash_all,
            network,
            digest,
            tls_verify,
            pull,
            access,
            iidfile,
            iidfile_raw,
            metadata_file,
            quiet,
            context,
        } => {
            if squash && squash_all {
                anyhow::bail!("cannot specify --squash-all with --squash");
            }
            cli::check_digest_flag(digest.as_deref()).map_err(anyhow::Error::msg)?;
            if !rm {
                anyhow::bail!(
                    "--rm=false is not supported by velarx: the containers of a build are always removed"
                );
            }
            let refused = unsupported.given();
            if !refused.is_empty() {
                anyhow::bail!(
                    "not supported by velarx's build yet: {}",
                    refused.join(", ")
                );
            }
            let cli::BuildExtra {
                format,
                pull_always,
                pull_never,
                volume,
                env,
                unsetenv,
                unsetlabel,
                build_arg_file,
                add_host,
                dns,
                dns_option,
                dns_search,
                cap_add,
                cap_drop,
                security_opt,
                ulimit,
                device,
                shm_size,
                logfile,
                logsplit,
                jobs,
                secret,
                ssh,
                allow,
                build_context,
                from_image,
                group_add,
                no_hosts,
                no_hostname,
                stdin: run_stdin,
                memory,
                memory_swap,
                cpu_period,
                cpu_quota,
                cpu_shares,
                cpuset_cpus,
                cpuset_mems,
                cgroup_parent,
                ipc,
                pid,
                uts,
                cgroupns,
                userns,
                userns_uid_map,
                userns_gid_map,
                userns_uid_map_user,
                userns_gid_map_group,
                isolation,
                retry,
                retry_delay,
                timestamp,
                source_date_epoch,
                rewrite_timestamp,
                omit_history,
                inherit_labels,
                skip_unused_stages,
                cache_ttl,
                output,
                compress: _,
                disable_content_trust: _,
                annotation,
                unsetannotation,
                inherit_annotations,
                created_annotation,
                identity_label,
                compat_volumes,
                cache_from,
                cache_to,
                layer_label,
                cpp_flag,
                sbom,
                sbom_scanner_image,
                sbom_scanner_command,
                sbom_merge_strategy,
                sbom_output,
                sbom_purl_output,
                sbom_image_output,
                sbom_image_purl_output,
                os_version,
                os_feature,
                http_proxy,
                disable_compression: _,
                compression_format,
                compression_level: _,
                force_compression: _,
                // (taken as the global options: src/cli/mod.rs)
                runtime_flag: _,
                hooks_dir: _,
            } = extra;
            let pull = match (pull_always, pull_never) {
                (true, true) => {
                    anyhow::bail!("--pull-always and --pull-never cannot be used together")
                }
                (true, false) => "always".to_string(),
                (false, true) => "never".to_string(),
                (false, false) => pull,
            };
            // the output of the build goes to the file; the ID stays on the
            // standard output
            let id_out = match &logfile {
                Some(path) => {
                    let log = std::fs::File::create(path)
                        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
                    let out = rustix::io::dup(rustix::stdio::stdout())?;
                    rustix::stdio::dup2_stdout(&log)?;
                    rustix::stdio::dup2_stderr(&log)?;
                    Some(std::fs::File::from(out))
                }
                None => None,
            };
            // (buildah's: chroot is not one velarx has)
            match isolation.as_deref() {
                None | Some("" | "oci" | "rootless") => {}
                Some(i) => anyhow::bail!(
                    "--isolation {i} is not supported by velarx: the steps run in the OCI runtime (oci)"
                ),
            }
            let memory_of = |s: &Option<String>| -> anyhow::Result<Option<i64>> {
                s.as_deref()
                    .map(|m| {
                        if m == "-1" {
                            Ok(-1)
                        } else {
                            cli::run::parse_memory_size(m)
                        }
                    })
                    .transpose()
            };
            let resources = velarx_wire::request::ResourceLimits {
                memory: memory_of(&memory)?,
                memory_swap: memory_of(&memory_swap)?,
                cpu_period,
                cpu_quota,
                cpu_shares,
                cpuset_cpus,
                cpuset_mems,
                ..Default::default()
            };
            let limited = resources.memory.is_some()
                || resources.memory_swap.is_some()
                || resources.cpu_period.is_some()
                || resources.cpu_quota.is_some()
                || resources.cpu_shares.is_some()
                || resources.cpuset_cpus.is_some()
                || resources.cpuset_mems.is_some();
            let more = velarx_wire::request::BuildRun {
                group_add,
                no_hosts: no_hosts.unwrap_or(false),
                no_hostname: no_hostname.unwrap_or(false),
                resources: limited.then_some(resources),
                cgroup_parent,
                ipc: crate::cli::run::opt_mode("--ipc", ipc)?,
                pid: crate::cli::run::opt_mode("--pid", pid)?,
                uts: crate::cli::run::opt_mode("--uts", uts)?,
                cgroupns: crate::cli::run::opt_mode("--cgroupns", cgroupns)?,
                userns: crate::cli::run::opt_mode("--userns", userns)?,
                uidmap: userns_uid_map,
                gidmap: userns_gid_map,
                subuidname: userns_uid_map_user,
                subgidname: userns_gid_map_group,
                ..Default::default()
            };
            // (podman's build waits 2s between the tries)
            let retry =
                client::policy::retry_of(retry, Some(retry_delay.as_deref().unwrap_or("2s")))
                    .map_err(anyhow::Error::msg)?;
            let source_date_epoch = match source_date_epoch {
                Some(t) => Some(t),
                None => match std::env::var("SOURCE_DATE_EPOCH")
                    .ok()
                    .filter(|v| !v.is_empty())
                {
                    Some(v) => Some(v.parse::<i64>().map_err(|_| {
                        anyhow::anyhow!("SOURCE_DATE_EPOCH `{v}` is not a number of seconds")
                    })?),
                    None => None,
                },
            };
            let flags = velarx_wire::buildopts::BuildFlags {
                from: from_image,
                retry,
                timestamp,
                source_date_epoch,
                rewrite_timestamp: rewrite_timestamp.unwrap_or(false),
                omit_history: omit_history.unwrap_or(false),
                inherit_labels: inherit_labels.unwrap_or(true),
                skip_unused_stages: skip_unused_stages.unwrap_or(true),
                jobs: jobs.unwrap_or(1),
                cache_ttl_ms: cache_ttl
                    .as_deref()
                    .map(client::policy::parse_duration)
                    .transpose()
                    .map_err(anyhow::Error::msg)?
                    .map(|d| d.as_millis() as u64),
                annotations: annotation
                    .iter()
                    .map(|a| velarx_proto::buildspec::BuildPair::parse(a))
                    .collect(),
                unset_annotations: unsetannotation,
                inherit_annotations: inherit_annotations.unwrap_or(true),
                created_annotation: created_annotation.unwrap_or(true),
                os_version,
                os_features: os_feature,
                compat_volumes: compat_volumes.unwrap_or(false),
                identity_label,
                cache_from,
                cache_to,
                layer_labels: layer_label
                    .iter()
                    .map(|a| velarx_proto::buildspec::BuildPair::parse(a))
                    .collect(),
                sbom: velarx_wire::sbom::SbomFlags {
                    preset: sbom,
                    scanner_image: sbom_scanner_image,
                    scanner_commands: sbom_scanner_command,
                    merge_strategy: sbom_merge_strategy,
                    // (the files of the engine's host, which is this one for
                    // a command that runs the engine)
                    output: sbom_output.map(absolute_path).transpose()?,
                    purl_output: sbom_purl_output.map(absolute_path).transpose()?,
                    image_output: sbom_image_output,
                    image_purl_output: sbom_image_purl_output,
                },
                proxy_env: cli::run::host_env(
                    false,
                    http_proxy.unwrap_or(true),
                    std::env::vars(),
                    &[],
                )
                .iter()
                .map(|a| velarx_proto::buildspec::BuildPair::parse(a))
                .collect(),
            };
            velarx_wire::buildopts::BuildFlagsCheck::check(&flags).map_err(anyhow::Error::msg)?;
            if let Some(c) = compression_format.as_deref() {
                velarx_proto::engine::LayerCompression::check_for_build(c)
                    .map_err(anyhow::Error::msg)?;
            }
            let outputs = output
                .iter()
                .map(|o| velarx_wire::buildopts::parse_output(o))
                .collect::<Result<Vec<_>, _>>()
                .map_err(anyhow::Error::msg)?;
            // (two tars one after the other are no archive one can read)
            if outputs
                .iter()
                .filter(|o| **o == velarx_wire::buildopts::Output::Tar(None))
                .count()
                > 1
            {
                anyhow::bail!("only one --output may be the standard output");
            }
            // (read as the build routes of the API read theirs)
            let parsed = velarx_wire::text::RunText {
                volumes: volume
                    .iter()
                    .map(|v| absolute_volume(v))
                    .collect::<Result<_, _>>()?,
                add_hosts: add_host,
                dns,
                dns_search,
                dns_options: dns_option,
                cap_add,
                cap_drop,
                security_opts: security_opt,
                ulimits: ulimit,
                devices: device,
                shm_size: shm_size
                    .as_deref()
                    .map(cli::run::parse_memory_size)
                    .transpose()?
                    .map(|s| s as u64),
                env,
                unset_env: unsetenv,
                unset_labels: unsetlabel,
                format,
                more,
            };
            let velarx_wire::text::RunParsed { run, env } = parsed
                .parse(|k| std::env::var(k).ok())
                .map_err(anyhow::Error::msg)?;
            // (buildah's words)
            let platform = (!platform.is_empty()).then(|| platform.join(","));
            if platform.is_some() && (os.is_some() || arch.is_some() || variant.is_some()) {
                anyhow::bail!("invalid --platform may not be used with --os, --arch, or --variant");
            }
            let platform =
                cli::platform_of(platform, os, arch, variant).map_err(anyhow::Error::msg)?;
            // buildah: the digests of one image only (the id files take
            // the id the build gives, as podman's)
            if let Some(file) = &metadata_file {
                if all_platforms || platform.as_deref().is_some_and(|p| p.contains(',')) {
                    anyhow::bail!(
                        "building multiple images, but metadata file {:?} can only be used to store information about one image",
                        file.display()
                    );
                }
            }
            let (access, auth) = build_access(&access)?;
            // `-`: the context is a tar on the standard input, or a
            // Containerfile with an empty context
            let stdin = if context.as_os_str() == "-" {
                Some(StdinContext::read()?)
            } else {
                None
            };
            // (an URL or a git repository: the engine fetches it, and the
            // Containerfile is a file of it)
            let remote = context
                .to_str()
                .filter(|c| velarx_wire::buildopts::is_remote_context(c))
                .map(str::to_string);
            let url_file = match file.as_slice() {
                [f] => f
                    .to_str()
                    .filter(|f| velarx_wire::buildopts::is_remote_file(f)),
                _ => None,
            }
            .map(str::to_string);
            if remote.is_some() {
                if file.len() > 1 || file.iter().any(|f| f.as_os_str() == "-") {
                    anyhow::bail!(
                        "a remote build context takes one -f file of it, or an URL, not several or `-`"
                    );
                }
                if ignorefile.is_some() {
                    anyhow::bail!("--ignorefile cannot be used with a remote build context");
                }
            } else if file.len() > 1
                && file.iter().any(|f| {
                    f.to_str()
                        .is_some_and(velarx_wire::buildopts::is_remote_file)
                })
            {
                anyhow::bail!("an URL as the Containerfile is the only -f file");
            }
            let context = match stdin {
                Some(_) => context,
                None if remote.is_some() => context,
                None => context.canonicalize().map_err(|e| {
                    anyhow::anyhow!(
                        "the build context {}: {e}",
                        velarx_wire::redact::urls(&context.display().to_string())
                    )
                })?,
            };
            if file.is_empty()
                && stdin.is_none()
                && remote.is_none()
                && !["Containerfile", "Dockerfile"]
                    .iter()
                    .any(|n| context.join(n).is_file())
            {
                anyhow::bail!(
                    "no Containerfile or Dockerfile specified or found in context directory, {}: no such file or directory",
                    context.display()
                );
            }
            // A Containerfile outside of the context is sent with it, and
            // the daemon takes it out before the build.
            let mut extra: Option<(String, Vec<u8>)> = None;
            let mut containerfile_outside = false;
            let mut dockerfile = match (file.as_slice(), &stdin) {
                ([_, ..], Some(StdinContext::Containerfile(_))) => anyhow::bail!(
                    "the Containerfile is the standard input: -f names one of a context"
                ),
                ([], Some(StdinContext::Containerfile(_))) => Some("Containerfile".to_string()),
                // (a path in the tar of the standard input)
                ([f], Some(StdinContext::Tar(..))) => Some(f.to_string_lossy().into_owned()),
                ([_, _, ..], Some(StdinContext::Tar(..))) => {
                    anyhow::bail!("several -f files need a context directory, not a tar on `-`")
                }
                ([], _) => None,
                ([_], _) if url_file.is_some() => None,
                ([f], None) if remote.is_some() => Some(f.to_string_lossy().into_owned()),
                // several files are one Containerfile, one after the other
                (files @ [_, _, ..], None) => {
                    let mut text = Vec::new();
                    let mut from_stdin = false;
                    for f in files {
                        let part = if f.as_os_str() == "-" {
                            use std::io::Read;
                            if std::mem::replace(&mut from_stdin, true) {
                                anyhow::bail!("-f - is given twice");
                            }
                            let mut part = Vec::new();
                            std::io::stdin().read_to_end(&mut part)?;
                            part
                        } else if is_pipe(f) {
                            std::fs::read(f).map_err(|e| {
                                anyhow::anyhow!("the Containerfile {}: {e}", f.display())
                            })?
                        } else {
                            let abs = containerfile_path(f, &context)?;
                            if abs.extension().is_some_and(|e| e == "in") {
                                preprocess(&abs, &context, &cpp_flag)?
                            } else {
                                std::fs::read(&abs).map_err(|e| {
                                    anyhow::anyhow!("the Containerfile {}: {e}", f.display())
                                })?
                            }
                        };
                        // (each file may start with a byte order mark)
                        text.extend_from_slice(part.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&part));
                        if !text.ends_with(b"\n") {
                            text.push(b'\n');
                        }
                    }
                    let name = format!(".velarx-containerfile-{}", std::process::id());
                    extra = Some((name.clone(), text));
                    containerfile_outside = true;
                    Some(name)
                }
                // `-f -`: the Containerfile is the standard input, the context a
                // directory; `-f <(...)` and `-f /dev/fd/N` are read as it is
                ([f], None) if f.as_os_str() == "-" || is_pipe(f) => {
                    use std::io::Read;
                    let mut text = Vec::new();
                    if f.as_os_str() == "-" {
                        std::io::stdin().read_to_end(&mut text)?;
                    } else {
                        text = std::fs::read(f).map_err(|e| {
                            anyhow::anyhow!("the Containerfile {}: {e}", f.display())
                        })?;
                    }
                    let name = format!(".velarx-containerfile-{}", std::process::id());
                    extra = Some((name.clone(), text));
                    containerfile_outside = true;
                    Some(name)
                }
                ([f], None) => {
                    // as buildah: where the command is, else in the context
                    let abs = containerfile_path(f, &context)?;
                    if abs.extension().is_some_and(|e| e == "in") {
                        let text = preprocess(&abs, &context, &cpp_flag)?;
                        let name = format!(".velarx-containerfile-{}", std::process::id());
                        extra = Some((name.clone(), text));
                        containerfile_outside = true;
                        Some(name)
                    } else {
                        match abs.strip_prefix(&context) {
                            Ok(rel) => Some(rel.to_string_lossy().to_string()),
                            Err(_) => {
                                let name = format!(".velarx-containerfile-{}", std::process::id());
                                extra = Some((name.clone(), std::fs::read(&abs)?));
                                containerfile_outside = true;
                                Some(name)
                            }
                        }
                    }
                }
            };
            let mut build_args = std::collections::HashMap::new();
            // the files first: an argument of the command line wins
            let mut from_files = Vec::new();
            for f in &build_arg_file {
                let text = std::fs::read_to_string(f).map_err(|e| {
                    anyhow::anyhow!("reading the build arguments of {}: {e}", f.display())
                })?;
                from_files.extend(
                    text.lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .map(str::to_string),
                );
            }
            for arg in from_files.into_iter().chain(build_arg) {
                match arg.split_once('=') {
                    Some((k, v)) => {
                        build_args.insert(k.to_string(), v.to_string());
                    }
                    None => {
                        if let Ok(v) = std::env::var(&arg) {
                            build_args.insert(arg, v);
                        }
                    }
                }
            }
            let mut labels = std::collections::HashMap::new();
            for lbl in label {
                let (k, v) = lbl.split_once('=').unwrap_or((&lbl, ""));
                labels.insert(k.to_string(), v.to_string());
            }
            // `--ignorefile`, else the ignore file of the Containerfile
            let cf_ignore = match (&ignorefile, &stdin) {
                (None, None) if remote.is_none() => {
                    let paths: Vec<std::path::PathBuf> = if file.is_empty() {
                        // (the one of the two that is used)
                        [context.join("Containerfile"), context.join("Dockerfile")]
                            .into_iter()
                            .filter(|p| p.is_file())
                            .take(1)
                            .collect()
                    } else {
                        file.iter()
                            .filter_map(|f| containerfile_path(f, &context).ok())
                            .collect()
                    };
                    containerfile_ignore(&paths)
                }
                _ => None,
            };
            // The engine applies (to what COPY sees) the ignore file of the
            // Containerfile it is given, else the context's: when the one
            // applied here is another (`--ignorefile`, that of a Containerfile
            // outside of the context, of several), it goes with the
            // Containerfile, added to the context, as `<name>.dockerignore`.
            let mut extras: Vec<(String, Vec<u8>)> = Vec::new();
            if let (None, Some(applied)) = (&stdin, ignorefile.as_ref().or(cf_ignore.as_ref())) {
                if ignorefile.is_some() || containerfile_outside {
                    if extra.is_none() {
                        let rel = match &dockerfile {
                            Some(d) => d.clone(),
                            None => ["Containerfile", "Dockerfile"]
                                .into_iter()
                                .find(|n| context.join(n).is_file())
                                .unwrap_or("Containerfile")
                                .to_string(),
                        };
                        let text = std::fs::read(context.join(&rel))
                            .map_err(|e| anyhow::anyhow!("the Containerfile {rel}: {e}"))?;
                        let name = format!(".velarx-containerfile-{}", std::process::id());
                        extra = Some((name.clone(), text));
                        containerfile_outside = true;
                        dockerfile = Some(name);
                    }
                    let text = std::fs::read(applied).map_err(|e| {
                        anyhow::anyhow!("the ignore file {}: {e}", applied.display())
                    })?;
                    if text.len() as u64 > velarx_wire::parse::MAX_FILE {
                        anyhow::bail!("the ignore file {} is too large", applied.display());
                    }
                    let name = dockerfile.clone().unwrap_or_default();
                    extras.push((format!("{name}.dockerignore"), text));
                }
            }
            extras.splice(0..0, extra);
            // (an ignore file does not leave the build without its file)
            let keep: Vec<String> = match &dockerfile {
                Some(d) => vec![d.clone()],
                None => vec!["Containerfile".to_string(), "Dockerfile".to_string()],
            };
            let getenv = |k: &str| std::env::var(k).ok();
            let mut secrets = Vec::new();
            for spec in &secret {
                let (id, source) =
                    velarx_wire::buildopts::parse_secret(spec, &|k| std::env::var_os(k).is_some())
                        .map_err(anyhow::Error::msg)?;
                secrets.push(
                    velarx_wire::buildopts::read_secret(&id, &source, &getenv)
                        .map_err(anyhow::Error::msg)?,
                );
            }
            let mut agents = Vec::new();
            let mut ssh_ids = Vec::new();
            for spec in &ssh {
                let (id, path) =
                    velarx_wire::buildopts::parse_ssh(spec, &getenv).map_err(anyhow::Error::msg)?;
                if ssh_ids.contains(&id) {
                    anyhow::bail!("--ssh {id} is given twice");
                }
                ssh_ids.push(id);
                agents.push(path);
            }
            let mut contexts = Vec::new();
            let mut named_dirs = Vec::new();
            for spec in &build_context {
                use velarx_wire::buildopts::{ContextSource, ContextValue};
                let (name, value) = velarx_wire::buildopts::parse_build_context(spec)
                    .map_err(anyhow::Error::msg)?;
                let source = match value {
                    ContextValue::Image(i) => ContextSource::Image(i),
                    ContextValue::Url(u) => ContextSource::Url(u),
                    ContextValue::Dir(d) => {
                        if stdin.is_some() || remote.is_some() {
                            anyhow::bail!(
                                "--build-context {name}: a directory goes with a context directory, not `-` or a remote context"
                            );
                        }
                        let dir =
                            velarx_wire::buildopts::context_dir(&d).map_err(anyhow::Error::msg)?;
                        let upload = velarx_wire::buildopts::upload_name(named_dirs.len());
                        if context.join(&upload).exists() {
                            anyhow::bail!("the context has a file named {upload}");
                        }
                        named_dirs.push((upload.clone(), dir));
                        ContextSource::Upload(upload)
                    }
                };
                contexts.push(velarx_wire::buildopts::NamedContextRequest { name, source });
            }
            let req = client::BuildImageRequest {
                dockerfile,
                containerfile_outside,
                containerfile_url: url_file,
                remote: remote.clone(),
                tags: tag,
                build_args,
                labels,
                no_cache,
                layers,
                target,
                platform,
                manifest,
                all_platforms,
                squash,
                squash_all,
                network,
                allow: velarx_base::entitlement::Entitlement::parse_list(&allow)
                    .map_err(|e| anyhow::anyhow!("--allow: {e}"))?,
                digest,
                tls_verify,
                pull: Some(pull),
                access,
                ask_credentials: false,
                run,
                env,
                unset_env: parsed.unset_env,
                unset_labels: parsed.unset_labels,
                secrets,
                contexts,
                ssh: ssh_ids,
                stdin: run_stdin.unwrap_or(false),
                flags,
            };

            // --logsplit: the output of the build for each platform goes to
            // its own file (a build for one platform at the start, those of
            // several when each starts)
            if logsplit.is_some() && logfile.is_none() {
                anyhow::bail!("cannot use --logsplit without --logfile");
            }
            let split = logfile
                .clone()
                .filter(|_| logsplit == Some(true))
                .map(LogSplit);
            if let Some(split) = &split {
                let platforms: Vec<&str> = req
                    .platform
                    .as_deref()
                    .unwrap_or("")
                    .split(',')
                    .filter(|p| !p.is_empty())
                    .collect();
                if let [one] = platforms.as_slice() {
                    split.switch(one)?;
                } else if platforms.is_empty() {
                    split.switch(&format!("linux/{}", cli::layout::host_go_arch()))?;
                }
            }
            let mut shown = shown_unless(quiet);
            let built = client.build_image(
                &req,
                Box::new(|w| match stdin {
                    Some(s) => s.write(w),
                    None if remote.is_some() => Ok(()),
                    None => context_tar(
                        &context,
                        ignorefile.as_deref().or(cf_ignore.as_deref()),
                        extras,
                        &keep,
                        &named_dirs,
                        w,
                    )
                    .map_err(std::io::Error::other),
                }),
                auth.as_ref(),
                &agents,
                &mut |event| match event {
                    client::BuildEvent::Progress(p) => shown.event(&p),
                    client::BuildEvent::Step(line) if !quiet => {
                        shown.next_step();
                        shown.print(&format!("{line}\n"));
                    }
                    client::BuildEvent::Output(output) if !quiet => shown.print(&output),
                    client::BuildEvent::Run {
                        stderr: false,
                        output,
                    } => shown.print(&output),
                    client::BuildEvent::Run {
                        stderr: true,
                        output,
                    } => shown.print_err(&output),
                    client::BuildEvent::Report(output) if !quiet => shown.print_err(&output),
                    client::BuildEvent::Platform(platform) => {
                        if let Some(split) = &split {
                            if let Err(e) = split.switch(&platform) {
                                shown.print_err(&format!("Error: {e}\n"));
                            }
                        }
                    }
                    _ => {}
                },
            );
            shown.finish();
            let image_id = built?;
            for output in &outputs {
                export_image(&client, &image_id, output)?;
            }
            // buildah: the id in the files, or else on the standard output
            let id = image_id_of(&client, &image_id)?;
            if let Some(path) = &iidfile {
                write_file(path, &velarx_shape::id_with_algorithm(&id))?;
            }
            if let Some(path) = &iidfile_raw {
                write_file(path, &id)?;
            }
            if let Some(path) = &metadata_file {
                // with --manifest the build gives the list, and the image
                // is its last instance (an instance added again moves to
                // the end)
                let image = match req.manifest {
                    Some(_) => client.manifest_inspect(&image_id, &Default::default())?
                        ["manifests"]
                        .as_array()
                        .and_then(|m| m.last())
                        .and_then(|m| m["digest"].as_str())
                        .ok_or_else(|| anyhow::anyhow!("the list {image_id} has no instance"))?
                        .to_string(),
                    None => image_id.clone(),
                };
                write_file(
                    path,
                    &build_metadata(&client.inspect_image(&image)?).to_string(),
                )?;
            }
            if iidfile.is_none() && iidfile_raw.is_none() {
                match id_out {
                    Some(mut out) => {
                        use std::io::Write;
                        writeln!(out, "{id}")?;
                    }
                    None => println!("{id}"),
                }
            }
        }
    }

    Ok(())
}

/// The absolute path of an output file of the command.
fn absolute_path(path: String) -> anyhow::Result<String> {
    std::path::absolute(&path)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| anyhow::anyhow!("{path}: {e}"))
}

/// The ignore file of the first of `files` that has one, as buildah:
/// `<file>.dockerignore` before `<file>.containerignore`.
fn containerfile_ignore(files: &[std::path::PathBuf]) -> Option<std::path::PathBuf> {
    files.iter().find_map(|f| {
        let name = f.as_os_str().to_os_string();
        ["dockerignore", "containerignore"].iter().find_map(|ext| {
            let mut path = name.clone();
            path.push(format!(".{ext}"));
            let path = std::path::PathBuf::from(path);
            path.is_file().then_some(path)
        })
    })
}

/// Whether `-f` names a pipe (a process substitution): it has no path to
/// canonicalize, and is read once.
fn is_pipe(f: &std::path::Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(f).is_ok_and(|m| m.file_type().is_fifo())
}

/// The path of a Containerfile named by `-f`: where the command is, else in
/// the context.
fn containerfile_path(
    f: &std::path::Path,
    context: &std::path::Path,
) -> anyhow::Result<std::path::PathBuf> {
    f.canonicalize()
        .or_else(|e| context.join(f).canonicalize().map_err(|_| e))
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow::anyhow!(
                "the specified Containerfile or Dockerfile does not exist, {}: no such file or directory",
                f.display()
            ),
            _ => anyhow::anyhow!("the Containerfile {}: {e}", f.display()),
        })
}

/// A Containerfile named `*.in` run through cpp(1) with buildah's options
/// (the context is searched for `#include "file"`; no macro is predefined,
/// and `//` is no comment).  As buildah, the output is used when cpp fails
/// but writes one, with its messages as a warning.
fn preprocess(
    file: &std::path::Path,
    context: &std::path::Path,
    flags: &[String],
) -> anyhow::Result<Vec<u8>> {
    use std::io::Write;
    let text = std::fs::read(file)
        .map_err(|e| anyhow::anyhow!("the Containerfile {}: {e}", file.display()))?;
    let mut child = std::process::Command::new("cpp")
        .args(["-E", "-iquote"])
        .arg(context)
        .args(["-traditional", "-undef", "-"])
        .args(flags)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                anyhow::anyhow!(
                    "{}: a Containerfile named *.in needs cpp: {e}",
                    file.display()
                )
            }
            _ => anyhow::anyhow!("preprocessing {}: cpp: {e}", file.display()),
        })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("cpp has no input"))?;
    // (cpp writes while it reads: the input goes from a thread of its own)
    let writer = std::thread::spawn(move || stdin.write_all(&text));
    let out = child.wait_with_output()?;
    writer
        .join()
        .map_err(|_| anyhow::anyhow!("writing to cpp panicked"))?
        .ok();
    if !out.status.success() {
        if out.stdout.is_empty() {
            anyhow::bail!(
                "preprocessing {}: cpp {}: {}",
                file.display(),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        if !out.stderr.is_empty() {
            eprintln!(
                "WARNING: ignoring the messages of cpp: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    }
    Ok(out.stdout)
}

/// `build --output`: the files of the image, from a container made of it
/// (never started), in a directory or a tar.
fn export_image(
    client: &client::EngineClient,
    image: &str,
    output: &velarx_wire::buildopts::Output,
) -> anyhow::Result<()> {
    use velarx_wire::buildopts::Output;
    let created = client.create_container(&client::CreateContainerRequest {
        image: image.to_string(),
        command: vec!["true".into()],
        // (a container of this build: `system prune --build` leaves it
        // while this process lives)
        labels: [(
            "io.velarx.build".to_string(),
            std::process::id().to_string(),
        )]
        .into(),
        ..Default::default()
    })?;
    let exported = (|| -> anyhow::Result<()> {
        let mut stream = client.export_container(&created.id)?;
        match output {
            Output::Tar(None) => to_stdout(&mut stream, "--output")?,
            _ => output.write(&mut stream, &mut |w| eprintln!("{w}"))?,
        }
        Ok(())
    })();
    let removed = client.remove_container_podman(
        &created.id,
        &client::RemoveContainer {
            force: true,
            ..Default::default()
        },
    );
    exported?;
    removed?;
    Ok(())
}

/// A volume of `build --volume`: a bind source given as a relative path
/// is made absolute (the engine runs elsewhere).
pub(super) fn absolute_volume(spec: &str) -> anyhow::Result<String> {
    let (source, rest) = spec.split_once(':').unwrap_or((spec, ""));
    if rest.is_empty()
        || !(source.starts_with('.') || source.contains('/'))
        || source.starts_with('/')
    {
        return Ok(spec.to_string());
    }
    let abs = std::path::absolute(source).map_err(|e| anyhow::anyhow!("{source}: {e}"))?;
    Ok(format!("{}:{rest}", abs.display()))
}

/// The context of `build -`: a tar (compressed with gzip or zstd, or not)
/// on the standard input, or a Containerfile.
pub(super) enum StdinContext {
    /// The start of the standard input, read to tell what it is, and the
    /// rest of it
    Tar(Vec<u8>, std::io::Stdin),
    Containerfile(Vec<u8>),
}

impl StdinContext {
    fn read() -> anyhow::Result<Self> {
        use std::io::{IsTerminal, Read};
        let mut stdin = std::io::stdin();
        if stdin.is_terminal() {
            anyhow::bail!("no context on the standard input (`build -`)");
        }
        // a tar's header is 512 bytes (its magic at 257)
        let mut head = Vec::with_capacity(512);
        (&mut stdin).take(512).read_to_end(&mut head)?;
        let compressed =
            velarx_tarsplit::decompress::sniff(&head) != velarx_tarsplit::decompress::Kind::None;
        if compressed || (head.len() > 262 && &head[257..262] == b"ustar") {
            return Ok(Self::Tar(head, stdin));
        }
        let mut file = head;
        stdin
            .take(velarx_wire::parse::MAX_FILE)
            .read_to_end(&mut file)?;
        Ok(Self::Containerfile(file))
    }

    /// Write the tar of the context to `out`.
    fn write(self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        use std::io::Read;
        match self {
            Self::Tar(head, stdin) => {
                let input = std::io::Cursor::new(head).chain(stdin.lock());
                let input = std::io::BufReader::new(input);
                std::io::copy(
                    &mut velarx_tarsplit::decompress::Decoder::detect(input)?,
                    out,
                )?;
                Ok(())
            }
            Self::Containerfile(text) => {
                let mut tar = tar::Builder::new(out);
                let mut h = tar::Header::new_gnu();
                h.set_size(text.len() as u64);
                h.set_mode(0o644);
                h.set_entry_type(tar::EntryType::Regular);
                tar.append_data(&mut h, "Containerfile", &text[..])?;
                tar.finish()
            }
        }
    }
}

/// Write the tar of a build context to `out`: links as links, nothing
/// followed out of it, what `.containerignore` (or `.dockerignore`) leaves
/// out not sent (but the ignore file and the Containerfile, `keep`);
/// `extra` is added at the top.
pub(super) fn context_tar(
    dir: &std::path::Path,
    ignorefile: Option<&std::path::Path>,
    extra: Vec<(String, Vec<u8>)>,
    keep: &[String],
    named: &[(String, std::path::PathBuf)],
    out: &mut dyn std::io::Write,
) -> anyhow::Result<()> {
    use std::io::Read;
    use velarx_wire::parse::{Ignore, MAX_FILE};
    let mut ignore = Ignore::default();
    // `--ignorefile`, else the context's
    let candidates: Vec<std::path::PathBuf> = match ignorefile {
        Some(f) => vec![f.to_path_buf()],
        None => [".containerignore", ".dockerignore"]
            .iter()
            .map(|n| dir.join(n))
            .collect(),
    };
    if let Some(f) = ignorefile {
        if !f.is_file() {
            anyhow::bail!("the ignore file {}: no such file", f.display());
        }
    }
    for path in candidates {
        // (in the context, a link is not followed out of it)
        let meta = if ignorefile.is_some() {
            std::fs::metadata(&path)
        } else {
            std::fs::symlink_metadata(&path)
        };
        if meta.is_ok_and(|m| m.is_file()) {
            let mut text = String::new();
            std::fs::File::open(&path)?
                .take(MAX_FILE)
                .read_to_string(&mut text)?;
            ignore = Ignore::parse(&text);
            break;
        }
    }
    struct Walk<'a> {
        ignore: Ignore,
        keep: &'a [String],
    }
    impl Walk<'_> {
        fn sent(&self, rel: &str) -> bool {
            !self.ignore.ignored(rel)
                || rel == ".containerignore"
                || rel == ".dockerignore"
                || self.keep.iter().any(|k| {
                    k == rel
                        || rel
                            .strip_prefix(k.as_str())
                            .is_some_and(|e| e == ".containerignore" || e == ".dockerignore")
                })
        }

        /// Whether something below `rel` may be sent though it is ignored.
        fn may_send_below(&self, rel: &str) -> bool {
            self.ignore.has_negations()
                || self.keep.iter().any(|k| k.starts_with(&format!("{rel}/")))
        }

        /// Add what the directory `dir` holds, named `rel` in the archive.
        fn add(
            self,
            tar: &mut tar::Builder<&mut dyn std::io::Write>,
            dir: &std::path::Path,
            rel: &str,
        ) -> anyhow::Result<()> {
            velarx_base::walk::Walk {
                max_depth: velarx_base::tree::MAX_DEPTH,
                sorted: true,
                skip_gone: false,
                lenient: false,
            }
            .run(
                velarx_base::tree::open_root(dir)?,
                rel.to_string(),
                &mut Context { walk: self, tar },
            )?;
            Ok(())
        }
    }
    /// The walk of a context into a tar: the state of a directory is its
    /// path in the archive.  An entry is read through the descriptor of its
    /// directory (`/proc/self/fd`), so a name replaced by a link is not
    /// followed.
    struct Context<'a, 'b> {
        walk: Walk<'a>,
        tar: &'a mut tar::Builder<&'b mut dyn std::io::Write>,
    }
    impl velarx_base::walk::Visit for Context<'_, '_> {
        type Dir = String;

        fn entry(
            &mut self,
            dir: std::os::fd::BorrowedFd<'_>,
            name: &std::ffi::OsStr,
            st: &rustix::fs::Stat,
            _: usize,
            rel: &mut String,
        ) -> std::io::Result<Option<String>> {
            let path = velarx_sys::fd::proc_path(&dir).join(name);
            let Some(name) = name.to_str().map(str::to_string) else {
                return Err(std::io::Error::other(format!(
                    "`{}` is not UTF-8",
                    std::path::Path::new(&*rel).join(name).display()
                )));
            };
            let child = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            let ft = rustix::fs::FileType::from_raw_mode(st.st_mode);
            let sent = self.walk.sent(&child);
            let tar = &mut *self.tar;
            let other = |e: anyhow::Error| std::io::Error::other(e.to_string());
            if ft == rustix::fs::FileType::Directory {
                if sent {
                    append_xattrs(tar, &path).map_err(other)?;
                    tar.append_dir(&child, &path)?;
                }
                return Ok((sent || self.walk.may_send_below(&child)).then_some(child));
            }
            let is_link = ft == rustix::fs::FileType::Symlink;
            if sent && (ft == rustix::fs::FileType::RegularFile || is_link) {
                if !is_link {
                    append_xattrs(tar, &path).map_err(other)?;
                }
                // append_path_with_name keeps a link a link.
                tar.append_path_with_name(&path, &child)?;
            } else if sent && ft == rustix::fs::FileType::Fifo {
                let meta = std::fs::symlink_metadata(&path)?;
                let mut h = tar::Header::new_gnu();
                h.set_metadata(&meta);
                h.set_entry_type(tar::EntryType::Fifo);
                h.set_size(0);
                tar.append_data(&mut h, &child, std::io::empty())?;
            }
            Ok(None)
        }
    }
    /// The xattrs a build keeps (the user's and the file capabilities) of
    /// `path`, as the PAX records of its entry.
    fn append_xattrs(
        tar: &mut tar::Builder<&mut dyn std::io::Write>,
        path: &std::path::Path,
    ) -> anyhow::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let Ok(names) = xattr::list(path) else {
            return Ok(());
        };
        let mut records = Vec::new();
        for n in names {
            let b = n.as_bytes();
            if !(b.starts_with(b"user.") || b == b"security.capability") {
                continue;
            }
            if let Some(v) = xattr::get(path, &n)? {
                let mut key = b"SCHILY.xattr.".to_vec();
                key.extend_from_slice(b);
                records.push((key, v));
            }
        }
        if !records.is_empty() {
            records.sort();
            let records: Vec<(String, &[u8])> = records
                .iter()
                .map(|(k, v)| (String::from_utf8_lossy(k).into_owned(), v.as_slice()))
                .collect();
            tar.append_pax_extensions(records.iter().map(|(k, v)| (k.as_str(), *v)))?;
        }
        Ok(())
    }
    let mut tar = tar::Builder::new(out);
    tar.follow_symlinks(false);
    for (name, content) in extra {
        let mut h = tar::Header::new_gnu();
        h.set_size(content.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        tar.append_data(&mut h, name, &content[..])?;
    }
    Walk { ignore, keep }.add(&mut tar, dir, "")?;
    // the named contexts at the top, under the names the request gives
    // them (the ignore file is the main context's)
    for (name, path) in named {
        tar.append_dir(name, path)?;
        Walk {
            ignore: Ignore::default(),
            keep: &[],
        }
        .add(&mut tar, path, name)?;
    }
    tar.finish()?;
    Ok(())
}

#[cfg(test)]
mod push_format_tests {
    use super::check_push_format;

    #[test]
    fn only_the_oci_format_is_pushed() {
        assert!(check_push_format(None).is_ok());
        assert!(check_push_format(Some("")).is_ok());
        assert!(check_push_format(Some("oci")).is_ok());
        for f in ["v2s2", "docker", "v2s1"] {
            let e = check_push_format(Some(f)).unwrap_err().to_string();
            assert!(
                e.contains("Docker image formats are not supported"),
                "{f}: {e}"
            );
        }
        let e = check_push_format(Some("OCI")).unwrap_err().to_string();
        assert!(e.contains("unknown format \"OCI\". Choose on of"), "{e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_metadata_of_a_build_has_buildx_keys() {
        let image = velarx_proto::workload::ImageRecord {
            id: "c".repeat(64),
            digest: format!("sha256:{}", "d".repeat(64)),
            manifest_type: "application/vnd.oci.image.manifest.v1+json".into(),
            manifest_size: 428,
            ..Default::default()
        };
        assert_eq!(
            build_metadata(&image),
            serde_json::json!({
                "containerimage.digest": format!("sha256:{}", "d".repeat(64)),
                "containerimage.config.digest": format!("sha256:{}", "c".repeat(64)),
                "containerimage.descriptor": {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha256:{}", "d".repeat(64)),
                    "size": 428,
                },
            })
        );
    }

    #[test]
    fn the_config_of_a_commit_is_read_as_podman_s() {
        let v = schema2_config(serde_json::json!({"Cmd": "sleep 1", "Env": ["A=1"]})).unwrap();
        assert_eq!(v["Cmd"], serde_json::json!(["sleep 1"]));
        let e = schema2_config(serde_json::json!({"Env": "A=1"})).unwrap_err();
        assert_eq!(
            e,
            "json: cannot unmarshal string into Go struct field Schema2Config.Env of type []string"
        );
        let e = schema2_config(serde_json::json!([1])).unwrap_err();
        assert_eq!(
            e,
            "json: cannot unmarshal array into Go value of type manifest.Schema2Config"
        );
    }

    fn hit(name: &str, description: &str, tag: &str) -> client::SearchHit {
        client::SearchHit {
            index: "r".into(),
            name: name.into(),
            description: description.into(),
            stars: 7,
            official: true,
            tag: tag.into(),
            ..Default::default()
        }
    }

    fn pull(
        id: &str,
        state: velarx_proto::workload::PullState,
        done: u64,
        total: u64,
    ) -> velarx_proto::workload::PullListed {
        velarx_proto::workload::PullListed {
            id: id.repeat(64).chars().take(64).collect(),
            names: vec!["docker.io/library/nginx:latest".into()],
            state,
            error: String::new(),
            percent: (done * 100).checked_div(total).unwrap_or(0),
            bytes_done: done,
            bytes_total: total,
            layers_done: 1,
            layers_total: 2,
            containers: 1,
            started_at: "2026-01-01T00:00:00+00:00".into(),
        }
    }

    #[test]
    fn pulls_are_reported_as_a_table_ids_or_json() {
        assert_eq!(pulls_report(&[], None, false, false).unwrap(), "");
        let pulls = [
            pull(
                "a",
                velarx_proto::workload::PullState::Running,
                62 << 20,
                100 << 20,
            ),
            pull("b", velarx_proto::workload::PullState::Failed, 0, 0),
        ];
        let table = pulls_report(&pulls, None, false, false).unwrap();
        let lines: Vec<&str> = table.lines().collect();
        assert!(
            lines[0].starts_with("ID") && lines[0].contains("PROGRESS"),
            "{table}"
        );
        assert!(lines[1].starts_with("aaaaaaaaaaaa "), "{table}");
        assert!(
            lines[1].contains("62%") && lines[1].contains("running"),
            "{table}"
        );
        assert!(
            lines[2].contains("failed") && lines[2].contains("0%"),
            "{table}"
        );
        assert_eq!(
            pulls_report(&pulls, None, true, false).unwrap(),
            "aaaaaaaaaaaa\nbbbbbbbbbbbb\n"
        );
        let full = pulls_report(&pulls, None, true, true).unwrap();
        assert!(full.starts_with(&"a".repeat(64)), "{full}");
        let json: serde_json::Value =
            serde_json::from_str(&pulls_report(&pulls, Some("json"), false, false).unwrap())
                .unwrap();
        assert_eq!(json[0]["State"], "running");
        assert_eq!(json[1]["LayersTotal"], 2);
    }

    #[test]
    fn search_reports_as_podman() {
        let long = "A minimal image based on Alpine Linux with a\ncomplete package index";
        let hits = [hit("r/a", long, ""), hit("r/b", "short", "")];
        let table = search_report(&hits, None, false, false, false).unwrap();
        let lines: Vec<&str> = table.lines().collect();
        assert!(lines[0].starts_with("NAME") && lines[0].contains("DESCRIPTION"));
        assert!(lines[1].ends_with("A minimal image based on Alpine Linux with a..."));
        let full = search_report(&hits, None, false, true, false).unwrap();
        assert!(full.contains("with a complete package index"), "{full}");
        let compat = search_report(&hits, None, false, false, true).unwrap();
        assert!(compat.lines().next().unwrap().contains("STARS"));
        assert!(compat.contains("[OK]"));
        let json: serde_json::Value =
            serde_json::from_str(&search_report(&hits, Some("json"), false, false, false).unwrap())
                .unwrap();
        assert_eq!(json[0]["Description"], long.replace('\n', " "));
        assert_eq!(json[0]["Official"], "[OK]");
        assert_eq!(json[1]["Automated"], "");
        let tags = [
            hit("r/a", "", "1"),
            hit("r/a", "", "2"),
            hit("r/b", "", "3"),
        ];
        let json: serde_json::Value =
            serde_json::from_str(&search_report(&tags, Some("json"), true, false, false).unwrap())
                .unwrap();
        assert_eq!(
            json,
            serde_json::json!([{"Name": "r/a", "Tags": ["1", "2"]}, {"Name": "r/b", "Tags": ["3"]}])
        );
        let table = search_report(&tags, None, true, false, false).unwrap();
        assert!(table.lines().next().unwrap().contains("TAG"));
        assert_eq!(search_report(&[], None, false, false, false).unwrap(), "");
    }

    #[test]
    fn signing_options_read_the_key_and_the_passphrase_files() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("k.private");
        let pass = dir.path().join("pass");
        std::fs::write(&key, "KEY\n").unwrap();
        std::fs::write(&pass, "secret\nsecond line\n").unwrap();
        assert_eq!(cli::SigningArgs::default().spec("push").unwrap(), None);
        let spec = cli::SigningArgs {
            sign_by_sigstore_private_key: Some(key.clone()),
            sign_passphrase_file: Some(pass.clone()),
            ..Default::default()
        }
        .spec("push")
        .unwrap()
        .unwrap();
        assert_eq!(
            (spec.key.as_str(), spec.passphrase.as_str()),
            ("KEY\n", "secret")
        );
        assert!(!format!("{spec:?}").contains("secret"));
        let e = cli::SigningArgs {
            sign_passphrase_file: Some(pass),
            ..Default::default()
        }
        .spec("push")
        .unwrap_err()
        .to_string();
        assert_eq!(
            e,
            "--sign-passphrase-file requires --sign-by-sigstore-private-key"
        );
        let e = cli::SigningArgs {
            sign_by: Some("k".into()),
            sign_by_sigstore: Some("p".into()),
            ..Default::default()
        }
        .spec("manifest push")
        .unwrap_err()
        .to_string();
        assert!(
            e.starts_with("--sign-by, --sign-by-sigstore is not supported for manifest push"),
            "{e}"
        );
        let e = cli::SigningArgs {
            sign_by_sigstore_private_key: Some(dir.path().join("none")),
            ..Default::default()
        }
        .spec("push")
        .unwrap_err()
        .to_string();
        assert!(e.starts_with("reading the signing key"), "{e}");
    }

    #[test]
    fn signing_is_refused_by_name() {
        assert!(cli::SigningArgs::default().refuse("image").is_ok());
        let e = cli::SigningArgs {
            sign_by: Some("k".into()),
            sign_passphrase_file: Some("/p".into()),
            ..Default::default()
        }
        .refuse("image")
        .unwrap_err()
        .to_string();
        assert_eq!(
            e,
            "--sign-by, --sign-passphrase-file is not supported: velarx signs no image"
        );
    }
}
