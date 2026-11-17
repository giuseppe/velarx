// SPDX-License-Identifier: Apache-2.0
use super::*;

pub(super) fn run_network_command(
    cmd: NetworkCommands,
    inv: &Invocation<'_>,
) -> anyhow::Result<()> {
    let client = get_client(inv)?;

    match cmd {
        NetworkCommands::Create {
            ignore,
            driver,
            subnet,
            gateway,
            opt,
            label,
            interface_name,
            ipam_driver,
            internal,
            ipv6,
            disable_dns,
            dns,
            ip_range,
            route,
            name,
        } => {
            let s = velarx_wire::addr::split_subnets(&subnet, &gateway)
                .map_err(|e| anyhow::anyhow!(e))?;
            let routes = route
                .iter()
                .map(|r| {
                    let r = velarx_wire::addr::Route::parse(r).map_err(|e| anyhow::anyhow!(e))?;
                    Ok(velarx_proto::workload::NetworkRoute {
                        destination: format!("{}/{}", r.destination, r.prefix),
                        gateway: r.gateway.to_string(),
                        metric: r.metric,
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let lease = match ip_range {
                Some(r) => {
                    let (start, end) = velarx_wire::addr::parse_ip_range(&r)
                        .ok_or_else(|| anyhow::anyhow!("invalid IP range `{r}`"))?;
                    Some(velarx_proto::workload::LeaseRange {
                        start: start.to_string(),
                        end: end.to_string(),
                    })
                }
                None => None,
            };
            let spec = velarx_proto::workload::NetworkSpec {
                name,
                driver,
                subnet: s.subnet,
                gateway: s.gateway,
                subnet6: s.subnet6,
                gateway6: s.gateway6,
                ipv6,
                lease,
                dns_enabled: !disable_dns,
                dns_servers: dns,
                labels: parse_pairs(&label).into_iter().collect(),
                internal,
                interface: interface_name,
                ipam_driver,
                options: parse_pairs(&opt).into_iter().collect(),
                routes,
            };
            let made = client.create_network(&spec, ignore)?;
            println!("{}", made.name);
        }
        NetworkCommands::List { out } => cli::report::networks(&client, &out)?,
        NetworkCommands::Exists { network } => {
            exit_with(if client.exists(client::Kind::Network, &network)? {
                0
            } else {
                1
            })
        }
        NetworkCommands::Inspect { format, networks } => {
            inspect_as_podman(&client, client::Kind::Network, &networks, format.as_deref())?
        }
        NetworkCommands::Remove {
            force,
            time,
            networks,
        } => {
            // as podman: the networks removed are said, the others
            // are errors (1 when they are not there)
            let (mut errors, mut missing, mut in_use) = (Vec::new(), false, false);
            let ended = cli::run::each_item(
                networks,
                |n| match client.remove_network(n, force, time) {
                    Err(e) if force && e.is_not_found() => Ok(()),
                    Ok(()) => {
                        println!("{n}");
                        Ok(())
                    }
                    Err(e) => Err(e),
                },
                |n, e| {
                    missing |= e.is_not_found();
                    in_use |= e.is_conflict();
                    errors.push(if e.is_not_found() {
                        format!("unable to find network with name or ID {n}: network not found")
                    } else {
                        e.to_string()
                    });
                },
            );
            for e in &errors {
                eprintln!("Error: {e}");
            }
            ended?;
            if !errors.is_empty() {
                exit_with(if in_use {
                    2
                } else if missing {
                    1
                } else {
                    125
                });
            }
        }
        NetworkCommands::Prune { force, filter } => {
            if !force
                && !confirm_prune(
                    "WARNING! This will remove all networks not used by at least one container.",
                )?
            {
                return Ok(());
            }
            for n in client.prune_networks(&filter)? {
                println!("{n}");
            }
        }
        NetworkCommands::Update {
            dns_add,
            dns_drop,
            network,
        } => {
            client.update_network(&network, &dns_add, &dns_drop)?;
            println!("{network}");
        }
        NetworkCommands::Connect {
            ip,
            ip6,
            mac_address,
            alias,
            network,
            container,
        } => {
            for (flag, value) in [("--ip", &ip), ("--ip6", &ip6)] {
                if let Some(v) = value
                    .as_ref()
                    .filter(|v| v.parse::<std::net::IpAddr>().is_err())
                {
                    anyhow::bail!(
                        "invalid argument \"{v}\" for \"{flag}\" flag: failed to parse IP: \"{v}\""
                    );
                }
            }
            if let Some(m) = mac_address
                .as_ref()
                .filter(|m| velarx_wire::addr::parse_mac(m).is_none())
            {
                anyhow::bail!("address {m}: invalid MAC address");
            }
            client.connect_network(
                &network,
                &container,
                ip.as_deref(),
                ip6.as_deref(),
                mac_address.as_deref(),
                &alias,
            )?;
        }
        NetworkCommands::Reload {
            all,
            latest,
            containers,
        } => {
            all_latest_or_named(all, latest, &containers, false)?;
            let containers: Vec<String> = if all {
                client
                    .list_containers(true, &[], false, false)?
                    .into_iter()
                    .map(|c| c.id)
                    .collect()
            } else {
                cli::run::named_or_latest(&client, latest, containers)?
            };
            // (as podman: a name that is not there is the only error)
            for c in &containers {
                if !client.exists(client::Kind::Container, c)? {
                    anyhow::bail!("no container with name or ID \"{c}\" found: no such container");
                }
            }
            each_container(&containers, |c| {
                let id = client.reload_network(c, all)?;
                if !id.is_empty() {
                    println!("{id}");
                }
                Ok(())
            })?;
        }
        NetworkCommands::Disconnect {
            force,
            network,
            container,
        } => {
            client.disconnect_network(&network, &container, force)?;
        }
    }

    Ok(())
}
