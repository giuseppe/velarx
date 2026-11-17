// SPDX-License-Identifier: Apache-2.0
//! `kube apply` (podman's `POST /libpod/kube/apply`): the documents of a
//! YAML body are created in a Kubernetes cluster, through its API server,
//! with the cluster and the credentials of a kubeconfig file of this host
//! (pkg/domain/infra/abi/apply.go).  Services and PersistentVolumeClaims
//! first, then Pods; other kinds are refused.  This process reads the
//! kubeconfig and the files it names ([`prepare`]) before the process
//! confines itself, and makes the requests ([`send`]) after: the one thing
//! it may do on the network is to connect to the port of the API server.

use serde_json::Value;
use std::path::Path;
use std::time::Duration;

/// How long a connection to the API server may take to open.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long one request may take, answer included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// How much of the body of a refusal is kept for the error.
const MAX_ERROR_BODY: usize = 64 * 1024;

/// A document to create: the YAML text as it was given, and the URL of
/// the API server it is posted to.
#[derive(Debug, Clone, PartialEq)]
pub struct Document {
    pub url: String,
    pub body: String,
}

/// What the requests trust and who they are, from the kubeconfig: PEM
/// texts and the bearer token.  Never logged.
#[derive(Default, Clone, PartialEq)]
pub struct Secrets {
    pub ca: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub token: Option<String>,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("ca", &self.ca.is_some())
            .field("cert", &self.cert.is_some())
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// What `kube apply` sends.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub documents: Vec<Document>,
    /// The port of the API server: the one TCP port the process may
    /// connect to
    pub port: u16,
    /// The server's certificate is not checked
    pub insecure: bool,
    pub secrets: Secrets,
}

#[derive(Debug, Default, Clone)]
pub struct ApplyOptions {
    /// The kubeconfig file
    pub kubeconfig: String,
    /// A CA file, or `insecure` to skip the server's verification
    pub ca_cert_file: String,
    /// default: `default`
    pub namespace: String,
}

/// The cluster and the user of a kubeconfig: podman takes the first of
/// each.
#[derive(Default, PartialEq)]
pub struct Cluster {
    pub server: String,
    pub ca_file: Option<String>,
    pub ca_data: Option<Vec<u8>>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub cert_data: Option<Vec<u8>>,
    pub key_data: Option<Vec<u8>>,
    pub token: Option<String>,
}

impl std::fmt::Debug for Cluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cluster")
            .field("server", &self.server)
            .field("ca_file", &self.ca_file)
            .field("ca_data", &self.ca_data.as_ref().map(Vec::len))
            .field("cert_file", &self.cert_file)
            .field("key_file", &self.key_file)
            .field("cert_data", &self.cert_data.as_ref().map(Vec::len))
            .field("key_data", &self.key_data.as_ref().map(|_| "<redacted>"))
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

fn s<'a>(v: &'a Value, path: &str) -> Option<&'a str> {
    v.pointer(path)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn data(v: &Value, path: &str) -> Result<Option<Vec<u8>>, String> {
    use base64::Engine;
    match s(v, path) {
        None => Ok(None),
        Some(b) => base64::engine::general_purpose::STANDARD
            .decode(b.trim())
            .map(Some)
            .map_err(|e| format!("kubeconfig {path}: {e}")),
    }
}

/// Read a kubeconfig.
pub fn parse_kubeconfig(text: &str) -> Result<Cluster, String> {
    let docs = super::yaml::parse_documents(text).map_err(|e| format!("kubeconfig: {e}"))?;
    let doc = docs.first().ok_or("kubeconfig: empty")?;
    let server = s(doc, "/clusters/0/cluster/server")
        .ok_or("kubeconfig: no cluster with a server")?
        .trim_end_matches('/')
        .to_string();
    Ok(Cluster {
        server,
        ca_file: s(doc, "/clusters/0/cluster/certificate-authority").map(str::to_string),
        ca_data: data(doc, "/clusters/0/cluster/certificate-authority-data")?,
        cert_file: s(doc, "/users/0/user/client-certificate").map(str::to_string),
        key_file: s(doc, "/users/0/user/client-key").map(str::to_string),
        cert_data: data(doc, "/users/0/user/client-certificate-data")?,
        key_data: data(doc, "/users/0/user/client-key-data")?,
        token: s(doc, "/users/0/user/token").map(str::to_string),
    })
}

/// The documents of a multi-document YAML text, as they are (numbers stay
/// numbers for the cluster), with their kinds; services and claims first,
/// as podman sorts them.
pub fn documents(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut docs = Vec::new();
    let mut cur = String::new();
    let flush = |cur: &mut String, docs: &mut Vec<String>| {
        if !cur.trim().is_empty() {
            docs.push(std::mem::take(cur));
        }
        cur.clear();
    };
    for line in text.lines() {
        if line.trim_end() == "---" || line.starts_with("--- ") {
            flush(&mut cur, &mut docs);
            continue;
        }
        cur.push_str(line);
        cur.push('\n');
    }
    flush(&mut cur, &mut docs);
    if docs.is_empty() {
        return Err("yaml file provided is empty, cannot apply to a cluster".into());
    }
    let mut out: Vec<(String, String)> = Vec::new();
    for d in docs {
        let parsed = super::yaml::parse_documents(&d)
            .map_err(|e| format!("unable to read kube YAML: {e}"))?;
        // (only comments: the header of what `generate` writes)
        if parsed.is_empty() {
            continue;
        }
        let kind = parsed
            .first()
            .and_then(|v| s(v, "/kind"))
            .ok_or("unable to read kube YAML: a document without a kind")?
            .to_string();
        if matches!(kind.as_str(), "Pod" | "Deployment" | "DaemonSet" | "Job") {
            out.push((kind, d));
        } else {
            out.insert(0, (kind, d));
        }
    }
    if out.is_empty() {
        return Err("yaml file provided is empty, cannot apply to a cluster".into());
    }
    Ok(out)
}

/// Where a document of `kind` is created in `namespace`.
pub fn endpoint(server: &str, namespace: &str, kind: &str) -> Result<String, String> {
    let what = match kind {
        "Service" => "services",
        "PersistentVolumeClaim" => "persistentvolumeclaims",
        "Pod" => "pods",
        k => return Err(format!("unsupported Kubernetes kind found: {k:?}")),
    };
    Ok(format!("{server}/api/v1/namespaces/{namespace}/{what}"))
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(Path::new(path)).map_err(|e| format!("{path}: {e}"))
}

fn text(pem: Vec<u8>) -> String {
    String::from_utf8_lossy(&pem).into_owned()
}

/// What `kube apply` sends, read and checked here: the documents of
/// `body` and where each goes, the port of the API server, and what to
/// trust and who to be, from the kubeconfig and the files it names (the
/// requests are made by a process that reads no file).
pub fn prepare(body: &str, opts: &ApplyOptions) -> Result<Request, String> {
    let docs = documents(body)?;
    let namespace = if opts.namespace.is_empty() {
        "default"
    } else {
        &opts.namespace
    };
    let kubeconfig = if opts.kubeconfig.is_empty() {
        std::env::var("KUBECONFIG").unwrap_or_default()
    } else {
        opts.kubeconfig.clone()
    };
    if kubeconfig.is_empty() {
        return Err("no kubeconfig: name one (--kubeconfig, KUBECONFIG)".into());
    }
    let cluster = parse_kubeconfig(&String::from_utf8_lossy(&read(&kubeconfig)?))?;
    let server = url::Url::parse(&cluster.server)
        .map_err(|e| format!("kubeconfig: the server {:?}: {e}", cluster.server))?;
    if !matches!(server.scheme(), "https" | "http") || server.host_str().is_none() {
        return Err(format!(
            "kubeconfig: the server {:?} is not an http(s) URL",
            cluster.server
        ));
    }
    let port = server
        .port_or_known_default()
        .ok_or_else(|| format!("kubeconfig: the server {:?} has no port", cluster.server))?;
    // every endpoint before the first request: an unknown kind sends nothing
    let documents = docs
        .into_iter()
        .map(|(kind, body)| {
            Ok(Document {
                url: endpoint(&cluster.server, namespace, &kind)?,
                body,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let insecure = opts.ca_cert_file.eq_ignore_ascii_case("insecure");
    let ca = match (
        insecure,
        opts.ca_cert_file.as_str(),
        &cluster.ca_file,
        &cluster.ca_data,
    ) {
        (true, ..) => None,
        (_, "", Some(f), _) => Some(read(f)?),
        (_, "", None, Some(d)) => Some(d.clone()),
        (_, "", None, None) => None,
        (_, f, _, _) => Some(read(f)?),
    };
    let identity = match (
        &cluster.cert_file,
        &cluster.key_file,
        &cluster.cert_data,
        &cluster.key_data,
    ) {
        (Some(c), Some(k), _, _) => Some((read(c)?, read(k)?)),
        (_, _, Some(c), Some(k)) => Some((c.clone(), k.clone())),
        _ => None,
    };
    let (cert, key) = identity.map_or((None, None), |(c, k)| (Some(text(c)), Some(text(k))));
    Ok(Request {
        documents,
        port,
        insecure,
        secrets: Secrets {
            ca: ca.map(text),
            cert,
            key,
            token: cluster.token,
        },
    })
}

fn client(insecure: bool, secrets: &Secrets) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());
    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    } else if let Some(pem) = &secrets.ca {
        let cert =
            reqwest::Certificate::from_pem(pem.as_bytes()).map_err(|e| format!("the CA: {e}"))?;
        builder = builder.add_root_certificate(cert);
    }
    if let (Some(cert), Some(key)) = (&secrets.cert, &secrets.key) {
        let id = reqwest::Identity::from_pkcs8_pem(cert.as_bytes(), key.as_bytes())
            .map_err(|e| format!("the client certificate: {e}"))?;
        builder = builder.identity(id);
    }
    builder.build().map_err(|e| e.to_string())
}

/// The error for a refused request: the status and what the server said,
/// at most `MAX_ERROR_BODY` bytes of it.
async fn refusal(mut res: reqwest::Response, url: &str) -> String {
    let status = res.status().as_u16();
    let mut body = Vec::new();
    while body.len() < MAX_ERROR_BODY {
        match res.chunk().await {
            Ok(Some(chunk)) => body.extend_from_slice(&chunk),
            Ok(None) | Err(_) => break,
        }
    }
    body.truncate(MAX_ERROR_BODY);
    let said = String::from_utf8_lossy(&body);
    let said = said.trim();
    if said.is_empty() {
        format!("{url}: status {status}")
    } else {
        format!("{url}: status {status}: {said}")
    }
}

/// Create the documents, in order, each by a POST of its body to its URL; a
/// server that refuses one ends the call (what was created before stays).
/// No proxy and no redirect: the process connects to the server alone.
pub async fn send(request: &Request) -> Result<(), String> {
    let client = client(request.insecure, &request.secrets)?;
    for doc in &request.documents {
        let mut req = client
            .post(&doc.url)
            .header("Content-Type", "application/yaml")
            .body(doc.body.clone());
        if let Some(t) = &request.secrets.token {
            req = req.bearer_auth(t);
        }
        let res = req.send().await.map_err(|e| format!("{}: {e}", doc.url))?;
        if !matches!(res.status().as_u16(), 200..=202) {
            return Err(refusal(res, &doc.url).await);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kubeconfig_gives_the_first_cluster_and_user() {
        let c = parse_kubeconfig(
            "apiVersion: v1\nclusters:\n- cluster:\n    server: https://k:6443/\n    certificate-authority-data: YWJj\n  name: c\nusers:\n- name: u\n  user:\n    token: t0k\n    client-certificate: /c.pem\n    client-key: /k.pem\n",
        )
        .unwrap();
        assert_eq!(c.server, "https://k:6443");
        assert_eq!(c.ca_data.as_deref(), Some(&b"abc"[..]));
        assert_eq!(c.token.as_deref(), Some("t0k"));
        assert_eq!(c.cert_file.as_deref(), Some("/c.pem"));
        assert!(parse_kubeconfig("apiVersion: v1\n").is_err());
    }

    #[test]
    fn documents_keep_their_text_and_pods_go_last() {
        let d = documents(
            "kind: Pod\nmetadata:\n  name: p\nspec:\n  replicas: 3\n---\nkind: Service\nmetadata:\n  name: s\n",
        )
        .unwrap();
        assert_eq!(d[0].0, "Service");
        assert_eq!(d[1].0, "Pod");
        assert!(d[1].1.contains("replicas: 3"));
        assert!(documents("").is_err());
        // a header of comments is no document
        let d = documents("# Save the output\n# of this file\nkind: Pod\nmetadata:\n  name: p\n")
            .unwrap();
        assert_eq!(d.len(), 1);
        let d = documents("# header\n---\nkind: Pod\n---\n# nothing\n").unwrap();
        assert_eq!(d.len(), 1);
        assert!(documents("metadata: {}\n").is_err());
        assert_eq!(
            endpoint("https://k", "ns", "PersistentVolumeClaim").unwrap(),
            "https://k/api/v1/namespaces/ns/persistentvolumeclaims"
        );
        assert!(endpoint("https://k", "ns", "Deployment").is_err());
    }
}
