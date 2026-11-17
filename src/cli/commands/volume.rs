// SPDX-License-Identifier: Apache-2.0
use super::*;

/// The volumes named, or with `--all` every volume (podman's check).
fn volumes_or_all(
    client: &client::EngineClient,
    all: bool,
    named: Vec<String>,
) -> anyhow::Result<Vec<String>> {
    if all == !named.is_empty() {
        anyhow::bail!("provide one or more volume names or use --all");
    }
    if !all {
        return Ok(named);
    }
    Ok(client
        .list_volumes(&[])?
        .into_iter()
        .map(|v| v.name)
        .collect())
}

pub(super) fn run_volume_command(cmd: VolumeCommands, inv: &Invocation<'_>) -> anyhow::Result<()> {
    let client = get_client(inv)?;

    match cmd {
        VolumeCommands::Create {
            ignore,
            name,
            driver,
            label,
            opt,
            uid,
            gid,
        } => {
            let mut options = parse_pairs(&opt);
            for (key, id) in [("uid", uid), ("gid", gid)] {
                if let Some(id) = id {
                    options.insert(key.to_string(), id.to_string());
                }
            }
            let volume = client.create_volume(
                &velarx_proto::workload::VolumeSpec {
                    name: name.unwrap_or_default(),
                    driver,
                    labels: parse_pairs(&label).into_iter().collect(),
                    options: options.into_iter().collect(),
                },
                ignore,
            )?;
            println!("{}", volume.name);
        }
        VolumeCommands::Export { name, output } => {
            let mut stream = client.export_volume(&name)?;
            match output {
                Some(path) => {
                    let mut file = std::fs::File::create(&path)?;
                    let result = std::io::copy(&mut stream, &mut file);
                    if result.is_err() {
                        let _ = std::fs::remove_file(&path);
                    }
                    result.map_err(|e| anyhow::anyhow!("exporting the volume: {e}"))?;
                }
                None => {
                    use std::io::IsTerminal;
                    if std::io::stdout().is_terminal() {
                        anyhow::bail!("refusing to write the archive to a terminal, use --output");
                    }
                    to_stdout(&mut stream, "exporting the volume")?;
                }
            }
        }
        VolumeCommands::Import { name, file } => {
            client.import_volume(
                &name,
                Box::new(|out| {
                    if file == "-" {
                        std::io::copy(&mut std::io::stdin().lock(), out)?;
                    } else {
                        std::io::copy(&mut std::fs::File::open(&file)?, out)?;
                    }
                    Ok(())
                }),
            )?;
        }
        VolumeCommands::Mount { name } => {
            println!("{}", client.mount_volume(&name)?);
        }
        VolumeCommands::Unmount { name } => {
            client.unmount_volume(&name)?;
            println!("{}", name);
        }
        // (velarx has no volume plugins: every volume is in its store)
        VolumeCommands::Reload => {}
        VolumeCommands::List { all: _, out } => cli::report::volumes(&client, &out)?,
        VolumeCommands::Exists { volume } => {
            exit_with(if client.exists(client::Kind::Volume, &volume)? {
                0
            } else {
                1
            })
        }
        VolumeCommands::Inspect {
            format,
            all,
            volumes,
        } => {
            let volumes = volumes_or_all(&client, all, volumes)?;
            inspect_as_podman(&client, client::Kind::Volume, &volumes, format.as_deref())?
        }
        VolumeCommands::Remove {
            force,
            all,
            time,
            volumes,
        } => {
            if !all && volumes.is_empty() {
                anyhow::bail!("choose either one or more volumes or all");
            }
            let volumes = if all {
                if !volumes.is_empty() {
                    anyhow::bail!("--all takes no volume");
                }
                client
                    .list_volumes(&[])?
                    .into_iter()
                    .map(|v| v.name)
                    .collect()
            } else {
                volumes
            };
            // (podman's -f: a volume that is not there is no error)
            cli::run::each_named_as(&volumes, force, &cli::run::Statuses::VOLUME_RM, |v| {
                client.remove_volume(v, force, time)
            })?
        }
        VolumeCommands::Prune { force, filter } => {
            if !force {
                let mut filters = vec!["dangling=true".to_string()];
                filters.extend(filter.iter().cloned());
                let unused = client.list_volumes(&filters)?;
                let names = unused.iter().map(|v| v.name.as_str());
                let mut warning = String::from("WARNING! This will remove all volumes not used by at least one container. The following volumes will be removed:");
                for n in names {
                    warning.push('\n');
                    warning.push_str(n);
                }
                if !confirm_prune(&warning)? {
                    return Ok(());
                }
            }
            for name in client.prune_volumes(&filter)? {
                println!("{name}");
            }
        }
    }

    Ok(())
}
