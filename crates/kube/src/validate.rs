// SPDX-License-Identifier: Apache-2.0
//! The fields of the Kubernetes objects `kube play` reads, for its
//! `validate` modes (`warn` reports the fields Kubernetes does not know,
//! `strict` refuses them), as podman decodes the documents strictly.
//!
//! The objects play maps are checked to their depth (pod, container,
//! ports, variables, mounts, probes, resources, security contexts); the
//! inside of the others (affinity, volume sources...) is not.

use serde_json::Value;

#[derive(Clone, Copy)]
enum T {
    Doc,
    Meta,
    PodSpec,
    Container,
    Port,
    Env,
    EnvFrom,
    EnvSource,
    VolumeMount,
    Volume,
    Resources,
    SecurityContext,
    PodSecurityContext,
    Probe,
    WorkloadSpec,
    Template,
    PvcSpec,
    /// Not checked inside
    Any,
}

fn fields(t: T, kind: &str) -> &'static [&'static str] {
    match t {
        T::Doc => match kind {
            "ConfigMap" => &[
                "apiVersion",
                "kind",
                "metadata",
                "data",
                "binaryData",
                "immutable",
            ],
            "Secret" => &[
                "apiVersion",
                "kind",
                "metadata",
                "data",
                "stringData",
                "type",
                "immutable",
            ],
            _ => &["apiVersion", "kind", "metadata", "spec", "status"],
        },
        T::Meta => &[
            "name",
            "namespace",
            "labels",
            "annotations",
            "uid",
            "generateName",
            "creationTimestamp",
            "resourceVersion",
            "generation",
            "deletionTimestamp",
            "deletionGracePeriodSeconds",
            "ownerReferences",
            "finalizers",
            "managedFields",
            "selfLink",
        ],
        T::PodSpec => &[
            "containers",
            "initContainers",
            "ephemeralContainers",
            "volumes",
            "restartPolicy",
            "terminationGracePeriodSeconds",
            "activeDeadlineSeconds",
            "dnsPolicy",
            "nodeSelector",
            "serviceAccountName",
            "serviceAccount",
            "automountServiceAccountToken",
            "nodeName",
            "hostNetwork",
            "hostPID",
            "hostIPC",
            "shareProcessNamespace",
            "securityContext",
            "imagePullSecrets",
            "hostname",
            "subdomain",
            "affinity",
            "schedulerName",
            "tolerations",
            "hostAliases",
            "priorityClassName",
            "priority",
            "dnsConfig",
            "readinessGates",
            "runtimeClassName",
            "enableServiceLinks",
            "preemptionPolicy",
            "overhead",
            "topologySpreadConstraints",
            "setHostnameAsFQDN",
            "os",
            "hostUsers",
            "schedulingGates",
            "resourceClaims",
            "resources",
        ],
        T::Container => &[
            "name",
            "image",
            "command",
            "args",
            "workingDir",
            "ports",
            "envFrom",
            "env",
            "resources",
            "resizePolicy",
            "restartPolicy",
            "volumeMounts",
            "volumeDevices",
            "livenessProbe",
            "readinessProbe",
            "startupProbe",
            "lifecycle",
            "terminationMessagePath",
            "terminationMessagePolicy",
            "imagePullPolicy",
            "securityContext",
            "stdin",
            "stdinOnce",
            "tty",
        ],
        T::Port => &["name", "hostPort", "containerPort", "protocol", "hostIP"],
        T::Env => &["name", "value", "valueFrom"],
        T::EnvFrom => &["prefix", "configMapRef", "secretRef"],
        T::EnvSource => &[
            "fieldRef",
            "resourceFieldRef",
            "configMapKeyRef",
            "secretKeyRef",
        ],
        T::VolumeMount => &[
            "name",
            "readOnly",
            "recursiveReadOnly",
            "mountPath",
            "subPath",
            "mountPropagation",
            "subPathExpr",
        ],
        T::Volume => &[
            "name",
            "hostPath",
            "emptyDir",
            "gcePersistentDisk",
            "awsElasticBlockStore",
            "gitRepo",
            "secret",
            "nfs",
            "iscsi",
            "glusterfs",
            "persistentVolumeClaim",
            "rbd",
            "flexVolume",
            "cinder",
            "cephfs",
            "flocker",
            "downwardAPI",
            "fc",
            "azureFile",
            "configMap",
            "vsphereVolume",
            "quobyte",
            "azureDisk",
            "photonPersistentDisk",
            "projected",
            "portworxVolume",
            "scaleIO",
            "storageos",
            "csi",
            "ephemeral",
            "image",
        ],
        T::Resources => &["limits", "requests", "claims"],
        T::SecurityContext => &[
            "capabilities",
            "privileged",
            "seLinuxOptions",
            "windowsOptions",
            "runAsUser",
            "runAsGroup",
            "runAsNonRoot",
            "readOnlyRootFilesystem",
            "allowPrivilegeEscalation",
            "procMount",
            "seccompProfile",
            "appArmorProfile",
        ],
        T::PodSecurityContext => &[
            "seLinuxOptions",
            "windowsOptions",
            "runAsUser",
            "runAsGroup",
            "runAsNonRoot",
            "supplementalGroups",
            "supplementalGroupsPolicy",
            "fsGroup",
            "sysctls",
            "fsGroupChangePolicy",
            "seccompProfile",
            "appArmorProfile",
            "seLinuxChangePolicy",
        ],
        T::Probe => &[
            "exec",
            "httpGet",
            "tcpSocket",
            "grpc",
            "initialDelaySeconds",
            "timeoutSeconds",
            "periodSeconds",
            "successThreshold",
            "failureThreshold",
            "terminationGracePeriodSeconds",
        ],
        T::WorkloadSpec => match kind {
            "Deployment" => &[
                "replicas",
                "selector",
                "template",
                "strategy",
                "minReadySeconds",
                "revisionHistoryLimit",
                "paused",
                "progressDeadlineSeconds",
            ],
            "DaemonSet" => &[
                "selector",
                "template",
                "updateStrategy",
                "minReadySeconds",
                "revisionHistoryLimit",
            ],
            "ReplicaSet" => &["replicas", "minReadySeconds", "selector", "template"],
            _ => &[
                "parallelism",
                "completions",
                "activeDeadlineSeconds",
                "podFailurePolicy",
                "successPolicy",
                "backoffLimit",
                "backoffLimitPerIndex",
                "maxFailedIndexes",
                "selector",
                "manualSelector",
                "template",
                "ttlSecondsAfterFinished",
                "completionMode",
                "suspend",
                "podReplacementPolicy",
                "managedBy",
            ],
        },
        T::Template => &["metadata", "spec"],
        T::PvcSpec => &[
            "accessModes",
            "selector",
            "resources",
            "volumeName",
            "storageClassName",
            "volumeMode",
            "dataSource",
            "dataSourceRef",
            "volumeAttributesClassName",
        ],
        T::Any => &[],
    }
}

/// What a field of a `t` holds.
fn child(t: T, kind: &str, key: &str) -> T {
    match (t, key) {
        (T::Doc, "metadata") | (T::Template, "metadata") => T::Meta,
        (T::Doc, "spec") => match kind {
            "Pod" => T::PodSpec,
            "Deployment" | "DaemonSet" | "ReplicaSet" | "Job" => T::WorkloadSpec,
            "PersistentVolumeClaim" => T::PvcSpec,
            _ => T::Any,
        },
        (T::WorkloadSpec, "template") => T::Template,
        (T::Template, "spec") => T::PodSpec,
        (T::PodSpec, "containers" | "initContainers") => T::Container,
        (T::PodSpec, "volumes") => T::Volume,
        (T::PodSpec, "securityContext") => T::PodSecurityContext,
        (T::Container, "ports") => T::Port,
        (T::Container, "env") => T::Env,
        (T::Container, "envFrom") => T::EnvFrom,
        (T::Container, "volumeMounts") => T::VolumeMount,
        (T::Container, "resources") => T::Resources,
        (T::Container, "securityContext") => T::SecurityContext,
        (T::Container, "livenessProbe" | "readinessProbe" | "startupProbe") => T::Probe,
        (T::Env, "valueFrom") => T::EnvSource,
        _ => T::Any,
    }
}

fn walk(v: &Value, t: T, kind: &str, path: &str, out: &mut Vec<String>) {
    match v {
        Value::Array(items) => {
            for (i, x) in items.iter().enumerate() {
                walk(x, t, kind, &format!("{path}[{i}]"), out);
            }
        }
        Value::Object(m) if !matches!(t, T::Any) => {
            let known = fields(t, kind);
            for (k, x) in m {
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                if !known.contains(&k.as_str()) {
                    out.push(format!("unknown field \"{p}\""));
                    continue;
                }
                walk(x, child(t, kind, k), kind, &p, out);
            }
        }
        _ => {}
    }
}

/// The fields Kubernetes does not know in a document, as messages naming
/// the kind and the path of each (`kube Pod: unknown field
/// "spec.containers[0].bogusfield"`).
pub fn unknown_fields(doc: &Value) -> Vec<String> {
    let kind = doc.get("kind").and_then(Value::as_str).unwrap_or("");
    let mut found = Vec::new();
    walk(doc, T::Doc, kind, "", &mut found);
    found
        .into_iter()
        .map(|f| format!("kube {kind}: {f}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yaml::parse_documents;

    #[test]
    fn the_unknown_fields_and_only_them() {
        let docs = parse_documents(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n  bogusmeta: 1\nspec:\n  containers:\n  - name: c\n    image: i\n    bogusfield: nope\n    ports:\n    - {containerPort: 80, bad: 1}\n    livenessProbe:\n      exec: {command: [x]}\n      periodSeconds: 1\n  affinity: {anything: {goes: here}}\n",
        )
        .unwrap();
        assert_eq!(
            unknown_fields(&docs[0]),
            [
                "kube Pod: unknown field \"metadata.bogusmeta\"",
                "kube Pod: unknown field \"spec.containers[0].bogusfield\"",
                "kube Pod: unknown field \"spec.containers[0].ports[0].bad\"",
            ]
        );
        let docs = parse_documents(
            "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d}\nspec:\n  replicas: 1\n  template:\n    metadata: {labels: {a: b}}\n    spec:\n      containers:\n      - {name: c, image: i, env: [{name: A, valueFrom: {nope: 1}}]}\n---\nkind: ConfigMap\nmetadata: {name: m}\ndata: {k: v}\nspec: x\n",
        )
        .unwrap();
        assert_eq!(
            unknown_fields(&docs[0]),
            ["kube Deployment: unknown field \"spec.template.spec.containers[0].env[0].valueFrom.nope\""]
        );
        assert_eq!(
            unknown_fields(&docs[1]),
            ["kube ConfigMap: unknown field \"spec\""]
        );
    }
}
