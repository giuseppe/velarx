<!-- SPDX-License-Identifier: Apache-2.0 -->
# The Kubernetes CRI frontend

`velarx-cri` serves the Container Runtime Interface (`runtime.v1`:
`RuntimeService` and `ImageService`) on a unix socket, so that a kubelet or
`crictl` can use velarx as the container runtime of a node.  It is a
separate program (`make build-cri`; `protoc` must be installed) and a client
of the engine's varlink interface `org.velarx.Engine` only: it needs no REST
API and starts no process.  What the engine cannot do is an error that names
it (gRPC `Unimplemented`), never worked around.

## Running it

```
velarx-cri                       # root: /run/velarx/cri.sock
velarx-cri --socket /run/velarx/cri.sock --engine-socket /run/velarx/engine/engine.sock
```

The CRI is run, and tested, as root only, as Kubernetes runs it.  Rootless
is not supported.

The engine (`velarx varlink`) must answer on `[engine] socket`
(`/run/velarx/engine/engine.sock`), started by `velarx-engine.socket` or by
hand.  A call that finds no engine is `Unavailable` and ends the frontend,
whose unit starts it again.

```
crictl --runtime-endpoint unix:///run/velarx/cri.sock \
       --image-endpoint   unix:///run/velarx/cri.sock ps
kubelet --container-runtime-endpoint unix:///run/velarx/cri.sock ...
```

The socket is `0600` and only root and the user of `velarx-cri` are served
(`SO_PEERCRED`), whatever the permissions of the socket become.

The cgroup driver is the engine's (`[engine] cgroup_manager`, shown by
`crictl runtime-config`; the kubelet's `cgroupDriver` must match).  The
runtime handlers are the default one and the runtimes of the engine's
`[runtimes]`, which is what a Kubernetes RuntimeClass names.

On a host with SELinux enforcing, label `velarx` (and `velarx-cri`)
`container_runtime_exec_t` and `velarx-monitor` `conmon_exec_t`
(`semanage fcontext -a -t conmon_exec_t /usr/bin/velarx-monitor` and
`restorecon`).  Otherwise a container that
opens `/dev/stderr` again (nginx, httpd) is refused and exits at once.

## Under systemd, with a kubelet

`make install` installs `velarx-cri.socket` and `velarx-cri.service` (when
`velarx-cri` was built).  The service requires the engine's socket unit and
ends when the engine can no longer be reached, so the next connection starts
it again.

```
systemctl enable --now velarx-cri.socket
kubelet --container-runtime-endpoint unix:///run/velarx/cri.sock ...
```

* `--sandbox-image IMAGE` is containerd's `sandbox_image`: the infra image
  of every sandbox, pulled when missing, kept by the kubelet's image
  garbage collection (give the name fully qualified).  Without it the infra
  container is the engine's `infra_image`.
* `/var/lib/kubelet/checkpoints` has to exist for checkpoints.
* The pod network is the engine's default (a bridge network) unless
  `--pod-network cni:` is given (below).
* Every container has a session keyring of its own unless `[containers]
  keyring = false`; a node with many pods can hit the key quota.

`tests/cri/kubelet.sh` (`make cri-kubelet`) runs a standalone kubelet
against `velarx-cri`.  `tests/cri/cluster.sh` (the `cluster` step of
`make cri-tests`, the pinned binaries of `tests/cri/versions` are downloaded)
runs a single-node cluster on it, as root: etcd, kube-apiserver,
kube-controller-manager, kube-scheduler and a kubelet that registers its
node, with the reference `bridge` and `host-local` CNI plugins.  It checks
that a Deployment and pods reach Running with addresses of the bridge, the
logs, `kubectl exec` (stdin, exit code), `attach -i` and `port-forward`,
the cgroups and limits of a Guaranteed, a Burstable and a BestEffort pod
(cgroupfs driver), that deleting them leaves no container, sandbox, cgroup,
lease or interface, and that the kubelet's eviction manager evicts a pod
under a memory pressure threshold.

## A single-node cluster: `contrib/velarx-kubeadm`

```
contrib/velarx-kubeadm up --smoke      # as root
contrib/velarx-kubeadm reset
contrib/velarx-kubeadm up --dry-run    # what it would write and run
```

`up` makes this host a one-node Kubernetes cluster whose runtime is
`velarx-cri`, with kubeadm.  It installs and downloads nothing: it needs
root, cgroup v2 with systemd, `kubelet`, `kubeadm`, `crictl` (and `kubectl`)
of one release, velarx with `velarx-cri`, `velarx-monitor` and `crun`, the
units `velarx-cri.socket`, `velarx-engine.socket` and `kubelet.service` with
the `10-kubeadm.conf` drop-in, `iptables` or `nft`, and the CNI plugins
`bridge`, `host-local`, `portmap` and `loopback` in `[network.cni]
bin_dirs`; `check` lists what is missing.  It loads `overlay` and
`br_netfilter`, sets the forwarding and `bridge-nf-call` sysctls
(`--no-host-config` only checks them), starts `velarx-cri` with
`--pod-network cni:velarx` and the pause image of kubeadm in a drop-in,
writes `/etc/cni/net.d/10-velarx.conflist` (`--cni none` leaves the pod
network to you), pulls the images and runs `kubeadm init` (no control-plane
taint), then waits for the node and CoreDNS.  `up` can be repeated; `reset`
undoes what it did (`--purge` also its module and sysctl files) and never
touches the engine's store.

## CNI

`velarx-cri --pod-network cni:` (or `cni:NAME`) puts the pods on the CNI
configuration of the engine's `[network.cni] conf_dir` (the first one by
file name, or NAME).  The engine runs the plugins as the CNI specification
says (ADD in order with `prevResult`, DEL in reverse with the cached result
of `[network.cni] cache_dir`); `CNI_ARGS` carries the identity of the pod.
Under systemd: `systemctl edit velarx-cri.service`, `ExecStart=` emptied and
set again with the option.

The runtime says `NetworkReady` false until the plugins' `STATUS` says they
are ready (CNI 1.1; an older configuration is ready when it exists).  By
the plugins' capabilities, the plugins get `portMappings`, `dns`, the
sandbox annotations, the bandwidth annotations
(`kubernetes.io/ingress-bandwidth`, `egress-bandwidth`) and the pod CIDR of
`UpdateRuntimeConfig` (`ipRanges`).  A bandwidth that no plugin can apply,
or that is not a positive quantity, refuses the sandbox; a pod CIDR is
refused when the pods are on the engine's own networks.

## exec, attach and port-forward

The RPCs answer with a URL of the streaming server of `velarx-cri`
(`--stream-address`, `127.0.0.1:0` by default, its only TCP listener); a URL
is good once and for a minute.  The streams are SPDY/3.1 or WebSocket.  A
port-forward session idle for `--stream-idle-timeout` seconds (1800; 0:
never) is closed.  Only TCP is forwarded: the engine connects inside the
pod's network namespace and passes the socket, the frontend copies.

## Requests that are refused

Nothing that cannot be given is ignored: it is answered with a code and a
reason.

* a container's `namespace_options` other than its pod's (the host's network
  or IPC namespace in a pod that has its own, a namespace of the container);
* a `recursive_read_only` mount that is not `readonly` with
  `PROPAGATION_PRIVATE` (the runtime must know `rro`: crun does, with
  `mount_setattr`);
* `PortForward` to a port that is not a TCP port;
* `PullImage` for a `runtime_handler` (there is one image store);
* a hugepage limit that is not 0 where the engine's cgroups have no
  `hugetlb`, and in a sandbox or an update of a running container;
* an ID-mapped mount with uid mappings and no gid mappings (or the reverse),
  or a mapping of length 0.

## Confinement

`velarx-cri` confines itself before it serves: no new privileges, no
capability; Landlock lets it reach only the directory of the engine's socket
(connect) and the checkpoint directory (no removal); seccomp is an allow-list
(no `execve`, no new process, no `mount`, sockets of UNIX, IPv4 and IPv6
only).  A kernel without Landlock does not run it.
