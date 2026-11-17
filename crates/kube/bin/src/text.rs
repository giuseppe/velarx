// SPDX-License-Identifier: Apache-2.0
//! What the commands print.

use velarx_kube::commands::{DownReport, PlayReport};

/// What a play made, as podman prints it.
pub fn play(report: &PlayReport) -> String {
    let mut out = String::new();
    if !report.volumes.is_empty() {
        out.push_str("Volumes:\n");
        for v in &report.volumes {
            out.push_str(&format!("{v}\n"));
        }
    }
    if !report.secret_ids.is_empty() {
        out.push_str("Secrets:\n");
        for s in &report.secret_ids {
            out.push_str(&format!("{s}\n"));
        }
    }
    for p in &report.pods {
        out.push_str(&format!("Pod:\n{}\n", p.id));
        match p.containers.len() {
            0 => continue,
            1 => out.push_str("Container:\n"),
            _ => out.push_str("Containers:\n"),
        }
        for c in &p.containers {
            out.push_str(&format!("{c}\n"));
        }
        out.push('\n');
    }
    out
}

/// What a down removed, as podman prints it: every heading, even of
/// nothing.
pub fn down(report: &DownReport) -> String {
    let mut out = String::new();
    for heading in ["Pods stopped:", "Pods removed:"] {
        out.push_str(&format!("{heading}\n"));
        for p in &report.pods {
            out.push_str(&format!("{p}\n"));
        }
    }
    out.push_str("Secrets removed:\n");
    for s in &report.secret_ids {
        out.push_str(&format!("{s}\n"));
    }
    out.push_str("Volumes removed:\n");
    for v in &report.volumes {
        out.push_str(&format!("{v}\n"));
    }
    out
}

/// The exit status of the service of a play: the codes of its containers,
/// as `--service-exit-code-propagation` says.
pub fn propagated(policy: &str, codes: &[i32]) -> u8 {
    let failed: Vec<i32> = codes.iter().copied().filter(|c| *c != 0).collect();
    let code = match policy {
        "any" => failed.first().copied().unwrap_or(0),
        "all" if !codes.is_empty() && failed.len() == codes.len() => failed[0],
        _ => 0,
    };
    // (an exit status is a byte)
    (code & 0xff) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_kube::commands::PlayedPod;

    /// What is printed is read from the typed report: the headings of a
    /// play follow what it made, those of a down are all there.
    #[test]
    fn a_play_and_a_down_are_printed_from_the_typed_reports() {
        let played = PlayReport {
            pods: vec![
                PlayedPod {
                    id: "p1".into(),
                    containers: vec!["c1".into(), "c2".into()],
                    init_containers: vec![],
                },
                PlayedPod {
                    id: "p2".into(),
                    containers: vec![],
                    init_containers: vec![],
                },
            ],
            volumes: vec!["v".into()],
            secret_ids: vec!["s".into()],
        };
        assert_eq!(
            play(&played),
            "Volumes:\nv\nSecrets:\ns\nPod:\np1\nContainers:\nc1\nc2\n\nPod:\np2\n"
        );
        let removed = DownReport {
            pods: vec!["p1".into()],
            volumes: vec![],
            secret_ids: vec!["s".into()],
        };
        assert_eq!(
            down(&removed),
            "Pods stopped:\np1\nPods removed:\np1\nSecrets removed:\ns\nVolumes removed:\n"
        );
        assert_eq!(
            down(&DownReport::default()),
            "Pods stopped:\nPods removed:\nSecrets removed:\nVolumes removed:\n"
        );
    }

    #[test]
    fn exit_code_propagation() {
        assert_eq!(propagated("none", &[1, 2]), 0);
        assert_eq!(propagated("any", &[0, 3, 4]), 3);
        assert_eq!(propagated("any", &[0, 0]), 0);
        assert_eq!(propagated("all", &[0, 3]), 0);
        assert_eq!(propagated("all", &[5, 3]), 5);
        assert_eq!(propagated("all", &[]), 0);
    }
}
