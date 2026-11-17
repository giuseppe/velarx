// SPDX-License-Identifier: Apache-2.0
use super::*;

/// podman's words for an auth file that is not there.
pub(super) fn check_authfile(path: &std::path::Path) -> anyhow::Result<()> {
    if let Err(e) = std::fs::metadata(path) {
        let why = match e.kind() {
            std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
            _ => e.to_string(),
        };
        anyhow::bail!(
            "credential file is not accessible: faccessat {}: {why}",
            path.display()
        );
    }
    Ok(())
}

/// What `image complete` sends: `--creds` and the certificates as they are;
/// of `--authfile` only the entries for the endpoints of the layers that
/// were pulled with credentials, which the daemon names.
pub(super) fn complete_access(
    client: &client::EngineClient,
    args: &cli::RegistryAccessArgs,
    image: &str,
) -> anyhow::Result<registry::auth::RegistryAccess> {
    let mut access = registry_access(
        client,
        &cli::RegistryAccessArgs {
            authfile: None,
            ..args.clone()
        },
        "",
        false,
    )?;
    if let Some(path) = &args.authfile {
        check_authfile(path)?;
        let scopes = client.credential_scopes(image)?;
        access.auths = registry::AuthConfig::load_file(path)
            .export_for(&scopes)
            .map_err(|e| anyhow::anyhow!(e))?;
    }
    Ok(access)
}

/// What `--creds`, `--authfile` and `--cert-dir` send to the server for
/// `reference`: for the other modules of the command line.
pub(crate) fn commands_registry_access(
    client: &client::EngineClient,
    args: &cli::RegistryAccessArgs,
    reference: &str,
    push: bool,
) -> anyhow::Result<registry::auth::RegistryAccess> {
    registry_access(client, args, reference, push)
}

/// What `--creds`, `--authfile` and `--cert-dir` send to the daemon for
/// `reference` (a push when `push`).  Of `--authfile` only the entries of
/// the endpoints the daemon will contact (the registry and its mirrors,
/// which only the daemon knows); without a reference, all of them.
pub(super) fn registry_access(
    client: &client::EngineClient,
    args: &cli::RegistryAccessArgs,
    reference: &str,
    push: bool,
) -> anyhow::Result<registry::auth::RegistryAccess> {
    // (a location of a transport, to pull from or to push to, is no docker
    // reference: the entry of `SCHEME://AUTHORITY`)
    if velarx_types::transport::ImageLocation::external(reference)?.is_some() {
        return transport_access(args, reference);
    }
    let mut access = access_without_file(args)?;
    if let Some(path) = &args.authfile {
        check_authfile(path)?;
        let file = registry::AuthConfig::load_file(path);
        access.auths = if reference.is_empty() {
            file.export()
        } else {
            file.export_for(&client.reference_credential_scopes(reference, push)?)
        }
        .map_err(|e| anyhow::anyhow!(e))?;
    }
    Ok(access)
}

/// What a push to a destination of an external scheme (`s3://bucket/x:1`)
/// sends: `--creds`, `--cert-dir`, and of `--authfile` the entry under
/// exactly `SCHEME://AUTHORITY` (`s3://bucket`), never what the text could
/// mean as a docker reference.
fn transport_access(
    args: &cli::RegistryAccessArgs,
    destination: &str,
) -> anyhow::Result<registry::auth::RegistryAccess> {
    let mut access = access_without_file(args)?;
    if let Some(path) = &args.authfile {
        check_authfile(path)?;
        let key = velarx_types::transport::ImageLocation::credential_key(destination).ok_or_else(
            || anyhow::anyhow!("`{destination}` is not a destination of a transport"),
        )?;
        access.auths = registry::AuthConfig::load_file(path)
            .export_exact(&key)
            .map_err(|e| anyhow::anyhow!(e))?;
    }
    Ok(access)
}

/// `--creds` and `--cert-dir`.
fn access_without_file(
    args: &cli::RegistryAccessArgs,
) -> anyhow::Result<registry::auth::RegistryAccess> {
    let mut access = registry::auth::RegistryAccess::default();
    if let Some(c) = &args.creds {
        access.creds = Some(registry::Credentials::parse_creds(c).map_err(|e| anyhow::anyhow!(e))?);
    }
    if let Some(dir) = &args.cert_dir {
        access.certs = Some(
            registry::certs::RawCerts::read_dir(dir)
                .map_err(|e| anyhow::anyhow!("--cert-dir `{}`: {e}", dir.display()))?,
        );
    }
    Ok(access)
}

/// What `build` sends: `--creds` and the certificates as they are; the
/// auth file stays here, and the build asks for the entries of the
/// endpoints of each reference it pulls (the references are known once the
/// daemon has read the Containerfile).
pub(super) fn build_access(
    args: &cli::RegistryAccessArgs,
) -> anyhow::Result<(registry::auth::RegistryAccess, Option<registry::AuthConfig>)> {
    let access = access_without_file(args)?;
    let Some(path) = &args.authfile else {
        return Ok((access, None));
    };
    check_authfile(path)?;
    let file = registry::AuthConfig::load_file(path);
    // (a file that cannot be read is an error now, not at the first pull)
    file.export_for(&[]).map_err(|e| anyhow::anyhow!(e))?;
    Ok((access, Some(file)))
}

/// `--authfile` or `--compat-auth-file` (a Docker config file has the same
/// `auths`): not both, as podman.
pub(super) fn one_authfile(
    authfile: Option<std::path::PathBuf>,
    compat: Option<std::path::PathBuf>,
) -> anyhow::Result<Option<std::path::PathBuf>> {
    if authfile.is_some() && compat.is_some() {
        anyhow::bail!(
            "options for paths to the credential file and to the Docker-compatible credential file can not be set simultaneously"
        );
    }
    Ok(authfile.or(compat))
}

/// Log in to a container registry
pub(super) struct LoginArgs {
    pub(super) username: Option<String>,
    pub(super) password: Option<String>,
    pub(super) password_stdin: bool,
    pub(super) authfile: Option<std::path::PathBuf>,
    pub(super) tls_verify: bool,
    pub(super) cert_dir: Option<std::path::PathBuf>,
    pub(super) get_login: bool,
    pub(super) verbose: bool,
}

/// `login --password-stdin`: as podman (a Go line scanner), the lines of
/// the input without their ends (`\n`, `\r\n`), put together.
pub(super) fn password_of_stdin(input: &str) -> String {
    input.lines().collect()
}

pub(super) fn run_login_command(
    config: &std::path::Path,
    args: LoginArgs,
    server: Option<String>,
) -> anyhow::Result<()> {
    use std::io::{self, Read, Write};

    let LoginArgs {
        username,
        password,
        password_stdin,
        authfile,
        tls_verify,
        cert_dir,
        get_login,
        verbose,
    } = args;
    let server = server.unwrap_or_else(|| "docker.io".to_string());
    // (the server of a push transport, `s3://bucket`: the entry of exactly
    // `SCHEME://AUTHORITY`, which nothing can check; a secret in the text
    // is refused before anything is asked)
    let transport_key = velarx_types::transport::ImageLocation::external(&server)?.and(
        velarx_types::transport::ImageLocation::credential_key(&server),
    );
    if verbose {
        let file = match &authfile {
            Some(p) => Ok(p.clone()),
            None => registry::auth::default_auth_file(),
        };
        if let Ok(file) = file {
            eprintln!("Used: {}", file.display());
        }
    }
    if get_login {
        // as podman: the user name of the server, else an error
        let found = registry::AuthConfig::load_file(
            &authfile
                .clone()
                .or_else(|| registry::auth::default_auth_file().ok())
                .unwrap_or_default(),
        )
        .lookup(&server, "")
        .map_err(|e| anyhow::anyhow!(e))?;
        return match found.map(|c| c.username).filter(|u| !u.is_empty()) {
            Some(u) => {
                println!("{u}");
                Ok(())
            }
            None => anyhow::bail!("not logged into {server}"),
        };
    }

    // (podman's checks: stdin cannot be both the user name and the password)
    if password_stdin {
        if password.is_some() {
            anyhow::bail!("can't specify both --password-stdin and --password");
        }
        if username.is_none() {
            anyhow::bail!("must provide --username with --password-stdin");
        }
    }

    let username = match username {
        Some(u) => u,
        None => {
            print!("Username: ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            input.trim().to_string()
        }
    };

    if username.is_empty() {
        anyhow::bail!("Username cannot be empty");
    }

    let password = if password_stdin {
        let mut input = String::new();
        io::stdin().lock().read_to_string(&mut input)?;
        password_of_stdin(&input)
    } else if let Some(p) = password {
        p
    } else {
        crate::cli::image_args::prompt_password("Password: ")?
    };

    if password.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }

    if let Some(key) = transport_key {
        registry::auth::store_credentials(authfile.as_deref(), &key, &username, &password)
            .map_err(|e| anyhow::anyhow!("Failed to save credentials: {}", e))?;
        println!("Login Succeeded!");
        return Ok(());
    }
    check_login(
        config,
        &server,
        &username,
        &password,
        tls_verify,
        cert_dir.as_deref(),
    )
    .map_err(|e| {
        // (podman's words for a registry it could not reach)
        if e.is::<RegistryUnreachable>() {
            e
        } else {
            anyhow::anyhow!("logging into \"{server}\": {e}")
        }
    })?;
    registry::auth::store_credentials(authfile.as_deref(), &server, &username, &password)
        .map_err(|e| anyhow::anyhow!("Failed to save credentials: {}", e))?;
    println!("Login Succeeded!");
    Ok(())
}

/// Log out from a container registry
pub(super) fn run_logout_command(
    all: bool,
    authfile: Option<std::path::PathBuf>,
    server: Option<String>,
) -> anyhow::Result<()> {
    if all {
        registry::auth::remove_all_credentials(authfile.as_deref())
            .map_err(|e| anyhow::anyhow!("Failed to remove credentials: {}", e))?;
        println!("Removed login credentials for all registries");
    } else {
        let server = server.unwrap_or_else(|| "docker.io".to_string());
        registry::auth::remove_credentials(authfile.as_deref(), &server)
            .map_err(|e| anyhow::anyhow!("Failed to remove credentials: {}", e))?;
        println!("Removed login credentials for {}", server);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--authfile` of a push to `s3://bucket/x:1` sends the entry of
    /// `s3://bucket` and nothing a docker reference could resolve to:
    /// not docker.io's, not a registry the first path segment looks like.
    #[test]
    fn test_a_push_to_a_transport_sends_the_entry_of_its_key_only() {
        use base64::Engine as _;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("auth.json");
        let entry = |u: &str| serde_json::json!({"auth": base64::engine::general_purpose::STANDARD.encode(format!("{u}:pw"))});
        std::fs::write(
            &file,
            serde_json::json!({"auths": {
                "docker.io": entry("hub"),
                "quay.io": entry("quay"),
                "s3://bucket": entry("mine"),
            }})
            .to_string(),
        )
        .unwrap();
        let args = cli::RegistryAccessArgs {
            authfile: Some(file),
            ..Default::default()
        };
        for destination in ["s3://bucket/x:1", "s3://bucket", "s3://bucket/quay.io/x:1"] {
            let access = transport_access(&args, destination).unwrap();
            assert_eq!(
                access.auths.keys().collect::<Vec<_>>(),
                ["s3://bucket"],
                "{destination}"
            );
        }
        let access = transport_access(&args, "s3://quay.io/x:1").unwrap();
        assert!(access.auths.is_empty(), "{:?}", access.auths);
        let access = transport_access(&args, "other://bucket/x").unwrap();
        assert!(access.auths.is_empty());
    }

    /// `login s3://Bucket/x` writes the entry of `s3://bucket` without
    /// asking a server, `logout` removes it, and a secret in the text is
    /// refused without being repeated.
    #[test]
    fn test_login_of_a_transport_writes_the_entry_of_its_key() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("auth.json");
        let args = |password: &str| LoginArgs {
            username: Some("AKID".into()),
            password: Some(password.into()),
            password_stdin: false,
            authfile: Some(file.clone()),
            tls_verify: true,
            cert_dir: None,
            get_login: false,
            verbose: false,
        };
        let config = dir.path().join("config.toml");
        run_login_command(&config, args("pw"), Some("s3://Bucket/x".into())).unwrap();
        let access = transport_access(
            &cli::RegistryAccessArgs {
                authfile: Some(file.clone()),
                ..Default::default()
            },
            "s3://BUCKET/y:1",
        )
        .unwrap();
        assert_eq!(access.auths.keys().collect::<Vec<_>>(), ["s3://bucket"]);
        let e = run_login_command(&config, args("pw"), Some("s3://AKID:SECRET@bucket".into()))
            .unwrap_err();
        let text = format!("{e:#} {e:?}");
        assert!(!text.contains("SECRET") && !text.contains("AKID"), "{text}");
        run_logout_command(false, Some(file.clone()), Some("s3://bucket".into())).unwrap();
        assert!(registry::AuthConfig::load_file(&file)
            .export_exact("s3://bucket")
            .unwrap()
            .is_empty());
    }
}
