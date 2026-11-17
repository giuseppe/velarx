// SPDX-License-Identifier: Apache-2.0
//! The command line of `velarx-kube`.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "velarx-kube",
    about = "Kubernetes YAML: play it as pods and containers, take it down, generate it from them, apply it to a cluster",
    disable_version_flag = true
)]
pub struct Cli {
    /// The configuration file of the engine this command starts when none
    /// answers
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
    /// The socket of the engine service (default: engine/engine.sock in the
    /// runtime directory)
    #[arg(long, global = true, value_name = "PATH")]
    pub engine_socket: Option<PathBuf>,
    /// Do not start the engine when none answers (something else does)
    #[arg(long, global = true)]
    pub no_start_engine: bool,
    /// The level of the messages of `velarx`, which `velarx kube` passes on
    /// to every program it runs: the warnings and errors of this command
    /// are lines of text on its standard error whatever it says
    #[arg(long, global = true)]
    pub log_level: Option<String>,
    /// The format of the messages (as `--log-level`)
    #[arg(long, global = true, default_value = "text")]
    pub log_format: String,
    /// Print the version and exit
    #[arg(long, short = 'V')]
    pub version: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Args, Clone, Default)]
pub struct RegistryAccess {
    /// Credentials (USERNAME[:PASSWORD]) for the registry
    #[arg(long)]
    pub creds: Option<String>,
    /// The auth file to use instead of the default ones
    #[arg(long)]
    pub authfile: Option<PathBuf>,
    /// A directory of certificates (*.crt, *.cert and *.key) for the registry
    #[arg(long)]
    pub cert_dir: Option<PathBuf>,
}

#[derive(Subcommand, Clone)]
#[allow(
    clippy::large_enum_variant,
    reason = "parsed once into one value; boxing a clap variant means a struct of its own for each"
)]
pub enum Command {
    #[command(about = "Create pods, containers and volumes from Kubernetes YAML")]
    Play {
        /// Replace the pods of the YAML that exist
        #[arg(long)]
        replace: bool,
        /// Start the pods (--start=false only creates them)
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
        start: bool,
        /// The networks of the pods (comma separated or repeated)
        #[arg(long)]
        network: Vec<String>,
        /// Verify the TLS certificates of the registries (--tls-verify=false)
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
        tls_verify: bool,
        /// The log driver of the containers
        #[arg(long)]
        log_driver: Option<String>,
        /// The user namespace of the pods
        #[arg(long)]
        userns: Option<String>,
        /// Annotations of the containers (key=value)
        #[arg(long)]
        annotation: Vec<String>,
        /// Options of the log driver of the containers (key=value)
        #[arg(long)]
        log_opt: Vec<String>,
        /// Publish a port of the pods: [[IP:]HOSTPORT:]CONTAINERPORT[/PROTO],
        /// over the YAML's
        #[arg(long)]
        publish: Vec<String>,
        /// YAML files of ConfigMaps the pods use (comma separated or repeated)
        #[arg(long)]
        configmap: Vec<String>,
        /// Static IP addresses of the pods, the n-th to the n-th pod (comma
        /// separated or repeated)
        #[arg(long)]
        ip: Vec<String>,
        /// Static MAC addresses of the pods, as --ip
        #[arg(long = "mac-address")]
        mac: Vec<String>,
        /// This command stays while the pods run, as the main process of a
        /// systemd unit: READY once they run, the stop of the unit stops
        /// them, and it exits when all their containers did
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set, num_args = 0..=1,
              default_missing_value = "true", require_equals = true)]
        service_container: bool,
        /// With --service-container, its exit status: none (0), all (the
        /// error of a container when all of them failed) or any (when one of
        /// them failed)
        #[arg(long, default_value = "none", value_parser = ["none", "all", "any"])]
        service_exit_code_propagation: String,
        /// Build the images of the YAML that have a directory of their name
        /// with a Containerfile in the context directory (by default those
        /// not here; --build=false: none)
        #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
        build: Option<bool>,
        /// The directory of the build directories (default: the current one)
        #[arg(long, value_name = "DIR")]
        context_dir: Option<PathBuf>,
        /// Stay until the pods exit or a SIGINT or SIGTERM comes, then
        /// remove what the YAML made (volumes too)
        #[arg(long, short)]
        wait: bool,
        /// Publish every containerPort of the YAML, on the same port of the
        /// host (by default only those with a hostPort)
        #[arg(long)]
        publish_all: bool,
        /// Print nothing of the pulls (the play prints none)
        #[arg(long, short)]
        quiet: bool,
        /// The containers keep the /etc/hosts of their image
        #[arg(long)]
        no_hosts: bool,
        /// The containers keep the /etc/hostname of their image
        #[arg(long)]
        no_hostname: bool,
        /// Name a container NAME, not POD-NAME
        #[arg(long)]
        no_pod_prefix: bool,
        /// The directory of the Localhost seccomp profiles (default
        /// /var/lib/kubelet/seccomp)
        #[arg(long, value_name = "DIR")]
        seccomp_profile_root: Option<String>,
        #[command(flatten)]
        access: RegistryAccess,
        /// The YAML files or http(s) addresses, or - for the standard input
        #[arg(required = true)]
        files: Vec<String>,
    },

    #[command(about = "Remove the pods a Kubernetes YAML made")]
    Down {
        /// Remove the volumes of the YAML too
        #[arg(long)]
        force: bool,
        /// The YAML file or http(s) address, or - for the standard input
        file: String,
    },

    #[command(
        about = "Create the YAML of a file, or of containers, pods and volumes, in a Kubernetes cluster"
    )]
    Apply {
        /// The kubeconfig of the cluster (default: $KUBECONFIG)
        #[arg(long, short)]
        kubeconfig: Option<PathBuf>,
        /// A CA file of the cluster, or `insecure`
        #[arg(long)]
        ca_cert_file: Option<String>,
        /// The namespace (default: default)
        #[arg(long)]
        ns: Option<String>,
        /// The YAML file or http(s) address, or - for the standard input
        #[arg(long, short)]
        file: Option<String>,
        /// With names: add a Service of the published ports
        #[arg(long, short)]
        service: bool,
        /// Containers, pods or volumes to make the YAML of
        names: Vec<String>,
    },

    #[command(about = "Generate Kubernetes YAML from containers, pods or volumes")]
    Generate {
        /// Add a Service of the published ports
        #[arg(long, short)]
        service: bool,
        /// The kind of the workload: pod, deployment, daemonset or job
        #[arg(long, short, default_value = "pod")]
        r#type: String,
        /// The replicas of a deployment
        #[arg(long, short = 'r', default_value_t = 1)]
        replicas: u32,
        /// Write the YAML to this file instead of the standard output
        #[arg(long, short)]
        filename: Option<PathBuf>,
        /// Add podman's own annotations of the containers (Kubernetes does
        /// not read them)
        #[arg(long)]
        podman_only: bool,
        /// Pods, containers or volumes
        #[arg(required = true)]
        names: Vec<String>,
    },

    /// Confine the process as a command does, try what it forbids and what it
    /// allows, and print the results as JSON (the tests)
    #[command(hide = true)]
    SelfTest {
        /// The TCP port a request may connect to
        #[arg(long)]
        connect_port: Option<u16>,
        /// A directory where none may
        #[arg(long)]
        outside: PathBuf,
    },
}
