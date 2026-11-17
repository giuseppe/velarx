// SPDX-License-Identifier: Apache-2.0
use super::*;

/// The text of `mode` in JSON, and the mode that JSON reads back as.
fn round<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(
    mode: &T,
    text: &str,
) {
    let json = serde_json::to_string(text).unwrap();
    assert_eq!(serde_json::to_string(mode).unwrap(), json, "{text:?}");
    assert_eq!(&serde_json::from_str::<T>(&json).unwrap(), mode, "{text:?}");
}

#[test]
fn a_namespace_mode_shows_as_the_text_it_was_read_from() {
    use NsMode::*;
    let s = |v: &str| v.to_string();
    for (text, mode) in [
        ("", Default),
        ("pod", Pod),
        ("private", Private),
        ("shareable", Shareable),
        ("none", Off),
        ("host", Host),
        ("container:abc", Container(s("abc"))),
        ("container:a:b", Container(s("a:b"))),
        ("ns:/proc/1/ns/pid", Ns(s("/proc/1/ns/pid"))),
    ] {
        assert_eq!(NsMode::parse(text), Ok(mode.clone()), "{text:?}");
        assert_eq!(mode.to_string(), text);
        round(&mode, text);
    }
    // (`default` is the default, as the empty text: podman's libpod word)
    assert_eq!(NsMode::parse("default"), Ok(Default));
}

#[test]
fn a_text_that_is_no_namespace_mode_is_an_error_of_its_reader() {
    for text in ["Host", "container:", "ns:", "ns:relative", "bridge", " "] {
        let e = NsMode::parse(text).unwrap_err();
        assert_eq!(e.text, text);
        assert!(e.to_string().contains(&format!("`{text}`")), "{e}");
        // the wire refuses it too, with the same words
        let json = serde_json::to_string(text).unwrap();
        let wire = serde_json::from_str::<NsMode>(&json).unwrap_err();
        assert!(
            wire.to_string().contains("invalid namespace mode"),
            "{wire}"
        );
    }
    assert!(NsMode::Host.is_joined() && NsMode::Container("x".into()).is_joined());
    assert!(!NsMode::Private.is_joined() && !NsMode::Default.is_joined());
    assert_eq!(NsMode::Container("x".into()).container(), Some("x"));
    assert_eq!(NsMode::Host.container(), None);
}

#[test]
fn a_user_namespace_choice_is_read_once() {
    use UsernsChoice::*;
    let s = |v: &str| v.to_string();
    for (text, mode) in [
        ("host", Host),
        ("private", Private),
        ("nomap", NoMap),
        ("auto", Auto(None)),
        ("auto:size=1024", Auto(Some(s("size=1024")))),
        ("auto:", Auto(Some(s("")))),
        ("keep-id", KeepId(None)),
        (
            "keep-id:uid=200,gid=210",
            KeepId(Some(s("uid=200,gid=210"))),
        ),
        ("ns:/proc/1/ns/user", Ns(s("/proc/1/ns/user"))),
        ("container:c1", Container(s("c1"))),
    ] {
        assert_eq!(UsernsChoice::parse(text), Ok(mode.clone()), "{text:?}");
        assert_eq!(mode.to_string(), text);
        round(&mode, text);
    }
    // (the empty text and `default` are the host's, shown as `host`)
    for text in ["", "default"] {
        assert_eq!(UsernsChoice::parse(text), Ok(Host));
    }
    assert_eq!(UsernsChoice::default(), Host);
    for text in [
        "host:x",
        "private:x",
        "nomap:1",
        "ns:",
        "ns:rel",
        "container:",
        "container",
        "bogus",
        "KEEP-ID",
    ] {
        assert!(UsernsChoice::parse(text).is_err(), "{text:?}");
    }
}

#[test]
fn the_cgroups_mode_splits_scope_from_enabled() {
    use CgroupsMode::*;
    for (text, mode) in [
        ("", Unset),
        ("enabled", Enabled),
        ("disabled", Disabled),
        ("no-conmon", NoConmon),
        ("split", Split),
        ("scope", Scope),
    ] {
        assert_eq!(CgroupsMode::parse(text), Ok(mode), "{text:?}");
        assert_eq!(mode.to_string(), text);
        round(&mode, text);
    }
    assert_eq!(Scope.split(), (Enabled, Some(CgroupMode::Scope)));
    assert_eq!(Split.split(), (Split, None));
    assert_eq!(Unset.split(), (Unset, None));
    assert_eq!(Unset.or_enabled(), Enabled);
    assert_eq!(Disabled.or_enabled(), Disabled);
    let e = CgroupsMode::parse("slice").unwrap_err();
    assert_eq!(
        e.to_string(),
        "invalid cgroup mode `slice`: enabled, disabled, no-conmon, split or scope"
    );
    assert!(CgroupMode::parse("unit").is_err());
    assert!(CgroupMode::parse("").is_err());
    round(&CgroupMode::Scope, "scope");
}

/// Every text is a network mode that shows as the same text, in the JSON of
/// a configuration too.
#[test]
fn a_network_mode_is_lossless() {
    for text in [
        "",
        "default",
        "private",
        "pod",
        "host",
        "none",
        "bridge",
        "bridge:",
        "bridge:net1",
        "pasta",
        "pasta:",
        "pasta:-T,none",
        "container:abc",
        "container:",
        "ns:/run/netns/x",
        "ns:relative",
        "provider:p",
        "provider:",
        "cni:mynet",
        "a,b",
        "mynet",
        "Host",
        "slirp4netns:port_handler=slirp4netns",
        "bridge2",
        "pasta2",
    ] {
        let mode = NetworkMode::parse(text);
        assert_eq!(mode.to_string(), text, "{text:?}");
        round(&mode, text);
    }
    use NetworkMode::*;
    let s = |v: &str| v.to_string();
    for (text, mode) in [
        ("", Unset),
        ("default", Default),
        ("private", Private),
        ("pod", Pod),
        ("host", Host),
        ("none", Off),
        ("bridge", Bridge(None)),
        ("bridge:", Bridge(Some(s("")))),
        ("bridge:net1", Bridge(Some(s("net1")))),
        ("pasta", Pasta(None)),
        ("pasta:-T,none", Pasta(Some(s("-T,none")))),
        ("container:abc", Container(s("abc"))),
        ("container:a:b", Container(s("a:b"))),
        ("ns:/run/netns/x", Ns(s("/run/netns/x"))),
        ("ns:relative", Ns(s("relative"))),
        ("provider:p", Provider(s("p"))),
        ("cni:mynet", Network(s("cni:mynet"))),
        ("a,b", Network(s("a,b"))),
        ("Host", Network(s("Host"))),
        (" host", Network(s(" host"))),
        ("slirp4netns", Network(s("slirp4netns"))),
        ("bridge2", Network(s("bridge2"))),
    ] {
        assert_eq!(NetworkMode::parse(text), mode, "{text:?}");
    }
    assert_eq!(NetworkMode::parse("provider:p").provider(), Some("p"));
    assert!(NetworkMode::parse("host").is_host() && !NetworkMode::parse("none").is_host());
    assert!(NetworkMode::parse("ns:/x").is_joined() && !NetworkMode::parse("none").is_joined());
    assert_eq!(NetworkMode::default().to_string(), "");
    // a list is a mode a piece, pasta's options are no list of modes
    assert_eq!(
        NetworkMode::parse("a, host").pieces(),
        [Network(s("a")), Host]
    );
    assert_eq!(
        NetworkMode::parse("pasta:-T,none").pieces(),
        [Pasta(Some(s("-T,none")))]
    );
    assert_eq!(NetworkMode::parse(" none").pieces(), [Off]);
}

/// The request carries the modes as typed fields and as the text it always
/// had: a request written by an older engine reads, and the schema of the
/// wire has the same `string`.
#[test]
fn the_create_request_carries_its_modes_typed() {
    let req: crate::request::CreateContainerRequest = serde_json::from_str(
        r#"{"image":"i","pid_mode":"host","ipc_mode":"container:db","uts_mode":"private",
            "cgroupns_mode":"ns:/run/cg","userns_mode":"keep-id:uid=1","network_mode":"pasta:-T",
            "cgroups":"scope","cgroup_mode":"scope"}"#,
    )
    .unwrap();
    assert_eq!(req.pid_mode, NsMode::Host);
    assert_eq!(req.ipc_mode, NsMode::Container("db".into()));
    assert_eq!(req.uts_mode, NsMode::Private);
    assert_eq!(req.cgroupns_mode, NsMode::Ns("/run/cg".into()));
    assert_eq!(req.userns_mode, UsernsChoice::KeepId(Some("uid=1".into())));
    assert_eq!(req.network_mode, NetworkMode::Pasta(Some("-T".into())));
    assert_eq!(req.cgroups, CgroupsMode::Scope);
    assert_eq!(req.cgroup_mode, Some(CgroupMode::Scope));
    let back = serde_json::to_value(&req).unwrap();
    assert_eq!(back["pid_mode"], "host");
    assert_eq!(back["userns_mode"], "keep-id:uid=1");
    assert_eq!(back["cgroups"], "scope");
    assert_eq!(back["cgroup_mode"], "scope");
    let req: crate::request::CreateContainerRequest =
        serde_json::from_str(r#"{"image":"i"}"#).unwrap();
    assert_eq!(req.userns_mode, UsernsChoice::Host);
    assert_eq!(req.pid_mode, NsMode::Default);
    assert_eq!(req.cgroup_mode, None);
    assert!(serde_json::to_value(&req)
        .unwrap()
        .get("cgroup_mode")
        .is_none());
    // none was the empty text: a request kept by an engine of before (the
    // record of the REST API, the request of a checkpoint) reads
    for cgroup_mode in [r#""""#, "null"] {
        let req: crate::request::CreateContainerRequest =
            serde_json::from_str(&format!(r#"{{"image":"i","cgroup_mode":{cgroup_mode}}}"#))
                .unwrap();
        assert_eq!(req.cgroup_mode, None);
        let pod: crate::pod::PodSpec =
            serde_json::from_str(&format!(r#"{{"cgroup_mode":{cgroup_mode}}}"#)).unwrap();
        assert_eq!(pod.cgroup_mode, None);
    }
    assert!(
        serde_json::from_str::<crate::request::CreateContainerRequest>(
            r#"{"image":"i","cgroup_mode":"slice"}"#
        )
        .is_err()
    );
    // a text that is no mode does not decode
    assert!(
        serde_json::from_str::<crate::request::CreateContainerRequest>(
            r#"{"image":"i","pid_mode":"bogus"}"#
        )
        .is_err()
    );
}

/// The `userns` of podman's SpecGenerator (`nsmode` and `value`) read in one
/// place, for a container and for a pod.
#[test]
fn the_userns_of_a_spec_generator_is_one_choice() {
    use UsernsChoice::*;
    let s = |v: &str| v.to_string();
    for (mode, value, want) in [
        ("", "", Host),
        ("default", "", Host),
        ("host", "", Host),
        // (podman ignores the value of the host's)
        ("host", "x", Host),
        ("private", "", Private),
        ("nomap", "", NoMap),
        ("auto", "", Auto(None)),
        ("auto", "size=5", Auto(Some(s("size=5")))),
        ("keep-id", "", KeepId(None)),
        ("keep-id", "uid=1", KeepId(Some(s("uid=1")))),
        ("container", "c", Container(s("c"))),
        ("ns", "/p", Ns(s("/p"))),
    ] {
        assert_eq!(
            UsernsChoice::from_spec(mode, value),
            Some(Ok(want)),
            "{mode} {value}"
        );
    }
    // a mode that is none here, or that takes no value
    for (mode, value) in [("private", "x"), ("nomap", "x"), ("slirp", "")] {
        assert_eq!(UsernsChoice::from_spec(mode, value), None, "{mode} {value}");
    }
    // a value the mode does not take is the error of `--userns`: a choice
    // that is made shows as a text that reads back (the wire)
    for (mode, value) in [("container", ""), ("ns", ""), ("ns", "relative")] {
        let e = UsernsChoice::from_spec(mode, value).unwrap().unwrap_err();
        assert!(e.to_string().contains("invalid user namespace mode"), "{e}");
    }
}
