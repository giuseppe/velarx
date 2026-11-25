// SPDX-License-Identifier: Apache-2.0
//! `--sbom`: the scanner image runs its commands on the root of the built
//! image and on the build context (mounted at `/.rootfs` and `/.context0`,
//! as buildah mounts them),
//! each writing a document to a file of its own; the documents are merged
//! and written to the places the options name, in a file of the host or in
//! a new layer of the image.

use super::*;
use velarx_wire::sbom::{merge, SbomResolve, Scan};

impl Build<'_> {
    /// The built image `id` with the SBOM options carried out: the image
    /// they leave (a layer more when one goes into the image).
    pub(super) async fn sbom(&mut self, id: String) -> BuildResult<String> {
        let flags = &self.opts.flags.sbom;
        let Some(scan) = flags.resolve().map_err(BuildError::Parse)? else {
            return Ok(id);
        };
        let (document, purl) = self.scan(&scan, &id).await?;
        // (files of the engine's host, as podman's service writes them)
        if let Some(path) = &flags.output {
            std::fs::write(path, &document)
                .map_err(|e| BuildError::StepFailed(format!("{path}: {e}")))?;
        }
        if let Some(path) = &flags.purl_output {
            std::fs::write(path, &purl)
                .map_err(|e| BuildError::StepFailed(format!("{path}: {e}")))?;
        }
        let mut files = Vec::new();
        if let Some(path) = &flags.image_output {
            files.push((path.clone(), document));
        }
        if let Some(path) = &flags.image_purl_output {
            files.push((path.clone(), purl));
        }
        if files.is_empty() {
            return Ok(id);
        }
        self.add_files(&id, &files).await
    }

    /// Run the commands of the scan, as buildah: a command that names the
    /// context `{CONTEXT}` scans it, else one that names `{ROOTFS}` scans
    /// the image (read only), any other is not run.  The documents merged,
    /// and the document of their package URLs.
    async fn scan(&mut self, scan: &Scan, image: &str) -> BuildResult<(Vec<u8>, Vec<u8>)> {
        let scanner = self.ensure_image(&scan.image, None).await?;
        let out_dir = self.new_dir("sbom-output")?;
        // (the scanner may run as any user)
        std::fs::set_permissions(
            &out_dir,
            std::os::unix::fs::PermissionsExt::from_mode(0o777),
        )?;
        // (the context where the engine has it, else a copy of it, which the
        // scan removes with its output: a descriptor a client sent is not
        // mounted, see `run::DirRoot`)
        let mut space = self.svc.scratch.reservation();
        let copy = match &self.ctx.path {
            Some(_) => None,
            None => Some(self.new_dir("sbom-context")?),
        };
        let result = self
            .scan_with(scan, image, &scanner, &out_dir, copy.as_deref(), &mut space)
            .await;
        remove_dir(&out_dir);
        if let Some(copy) = &copy {
            remove_dir(copy);
        }
        result
    }

    /// The scan, its output in `out_dir`, the context copied into `copy`
    /// when it is given.
    async fn scan_with(
        &mut self,
        scan: &Scan,
        image: &str,
        scanner: &str,
        out_dir: &Path,
        copy: Option<&Path>,
        space: &mut Reservation,
    ) -> BuildResult<(Vec<u8>, Vec<u8>)> {
        const ROOTFS: &str = "/.rootfs";
        const SCANS: &str = "/.scans";
        const CONTEXT: &str = "/.context0";
        let context = match (copy, &self.ctx.path) {
            (Some(dir), _) => {
                let root = self.ctx.fd()?;
                self.copy_from_dir(&root, "", dir, None, space)
                    .await
                    .map_err(|e| {
                        BuildError::StepFailed(format!("the copy of the context for the scan: {e}"))
                    })?
                    .0
            }
            (None, Some(path)) => path.clone(),
            (None, None) => return Err(BuildError::StepFailed("no context to scan".into())),
        };
        self.label_dirs(&[out_dir, &context])?;
        let mounts = vec![
            run::mount_config(run::bind_of(out_dir, SCANS, true, None))?,
            run::mount_config(run::bind_of(&context, CONTEXT, false, None))?,
        ];
        let mut docs = Vec::new();
        for words in &scan.commands {
            let names = |p: &str| words.iter().any(|w| w.contains(p));
            let dir = if names("{CONTEXT}") {
                CONTEXT
            } else if names("{ROOTFS}") {
                ROOTFS
            } else {
                continue;
            };
            let n = docs.len();
            let argv: Vec<String> = words
                .iter()
                .map(|w| {
                    w.replace("{CONTEXT}", dir)
                        .replace("{ROOTFS}", dir)
                        .replace("{OUTPUT}", &format!("{SCANS}/scan{n}.json"))
                })
                .collect();
            let (entry, args) = argv
                .split_first()
                .ok_or_else(|| BuildError::StepFailed("an empty SBOM scanner command".into()))?;
            self.say(format!("SBOM: {}\n", argv.join(" "))).await;
            let step = run::StepId::new(self.svc);
            let req = CreateContainerRequest {
                image: scanner.to_string(),
                entrypoint: vec![entry.clone()],
                command: args.to_vec(),
                id: Some(step.id().to_string()),
                labels: [(BUILD_LABEL.to_string(), std::process::id().to_string())].into(),
                mounts: mounts.clone(),
                mount: vec![format!("type=image,src={image},dst={ROOTFS}")],
                network_mode: build_network(self.opts.network.as_deref())?.unwrap_or_default(),
                ..CreateContainerRequest::default()
            };
            let cs = self.svc.container_service.clone();
            let id = cs.create(req).await?;
            let code = self.run_container(&id).await;
            if let Err(e) = cs.delete(&id, true).await {
                warn!("Cannot remove the build container {id}: {e}");
            }
            let code = code?;
            if code != 0 {
                return Err(BuildError::StepFailed(format!(
                    "running scanning command `{}`: exit code {code}",
                    argv.join(" ")
                )));
            }
            docs.push(
                read_output(&out_dir.join(format!("scan{n}.json"))).map_err(|e| {
                    BuildError::StepFailed(format!(
                        "the SBOM scanner `{}`: {SCANS}/scan{n}.json: {e}",
                        argv.join(" ")
                    ))
                })?,
            );
        }
        merge(scan.merge, &docs).map_err(BuildError::StepFailed)
    }

    /// Under SELinux, the directories the build made for the scanner get
    /// the label containers share (as for a RUN step), those of the user
    /// are left alone.
    fn label_dirs(&self, dirs: &[&Path]) -> BuildResult<()> {
        use crate::container::selinux;
        if !selinux::enabled() {
            return Ok(());
        }
        let c = selinux::Contexts::host();
        let label = format!("{}:{}:{}:s0", c.file_user, c.file_role, c.file_type);
        for dir in dirs {
            if dir.starts_with(&self.svc.work_dir) {
                selinux::relabel_path(dir, &label, &[]).map_err(|e| {
                    BuildError::StepFailed(format!("cannot relabel {}: {e}", dir.display()))
                })?;
            }
        }
        Ok(())
    }

    /// A layer on the image `id` with `files` (path in the image and
    /// content).
    async fn add_files(&mut self, id: &str, files: &[(String, Vec<u8>)]) -> BuildResult<String> {
        let rec = self.svc.image_service.get(id).await?;
        let tocs = self.svc.image_service.layer_tocs(&rec).await?;
        let refs: Vec<&Toc> = tocs.iter().collect();
        let tree = MergedTree::build(&refs).map_err(BuildError::Parse)?;
        let source = self.new_dir("sbom-files")?;
        let upper = self.new_dir("upper")?;
        let result = async {
            let mut space = self.svc.scratch.reservation();
            for (n, (path, content)) in files.iter().enumerate() {
                std::fs::write(source.join(n.to_string()), content)?;
                // (a job of its own: with several files, each would go
                // into a directory named by its destination)
                let mut job = CopyJob::new(Source::Context);
                job.items.push(Item {
                    src: n.to_string(),
                    dst: velarx_wire::cp::clean_path(&format!("/{path}")),
                    ..Default::default()
                });
                job.parents = Self::parents(&tree, &item_paths(&job));
                job.limits = self.svc.job_limits(&mut space)?;
                self.svc
                    .runner
                    .run(job, &upper, JobSource::Dir(source.clone()), &self.cancel)
                    .await
                    .map_err(|e| BuildError::StepFailed(e.to_string()))?;
            }
            let annotations: HashMap<String, String> = serde_json::from_str::<Value>(&rec.manifest)
                .ok()
                .and_then(|m| m["annotations"].as_object().cloned())
                .into_iter()
                .flatten()
                .filter(|(k, _)| !crate::services::image::is_merged_annotation(k))
                .filter_map(|(k, v)| Some((k, v.as_str()?.to_string())))
                .collect();
            let (progress, forwarded) = self.blobs();
            let opts = CommitOptions {
                created_by: "velarx build --sbom".into(),
                digest: Some(self.digest),
                hold: self.hold.as_ref().map(|h| h.name().to_string()),
                platform: self.platform.clone(),
                progress: Some(progress),
                created: self.created(),
                omit_history: self.opts.flags.omit_history,
                cancel: self.cancel.clone(),
                annotations,
                walk: dirtar::Options {
                    mtime: self.mtime(),
                    ..Default::default()
                },
                ..CommitOptions::default()
            };
            let committed = self
                .svc
                .image_service
                .commit_dir(Some(id), Some(&upper), &opts)
                .await;
            drop(opts);
            let _ = forwarded.await;
            let new = committed.map_err(|e| self.stopped(e))?;
            self.say(format!("--> {}\n", &new[..12.min(new.len())]))
                .await;
            self.intermediates.push(new.clone());
            Ok(new)
        }
        .await;
        remove_dir(&source);
        remove_dir(&upper);
        result
    }
}

/// A file the scanner wrote: a regular file, never what a link it made
/// points to (a file of the engine's host).
fn read_output(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut out = Vec::new();
    file.read_to_end(&mut out)?;
    Ok(out)
}
