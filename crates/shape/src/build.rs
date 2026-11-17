// SPDX-License-Identifier: Apache-2.0
//! The JSON lines of the answers of podman's and Docker's builds, made of
//! the events the engine tells as a build goes (`BuildEvent`, a JSON
//! document each line of the pipe of `ImageBuild`): libpod's `stream`
//! lines, Docker's `aux` and its messages, the error.

use velarx_proto::buildspec::{BuildEvent, BuildEventKind, BuildStream};

/// How the events of a build are told to its client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildLines {
    /// The output of the steps is not told (but that of the RUNs)
    pub quiet: bool,
    /// Docker's messages and defaults
    pub docker: bool,
}

impl BuildLines {
    /// The lines of the answer for the event `line` (a `BuildEvent`, its
    /// newline or not), written to `out`: none for an event the client is
    /// not told.  A line that is no event is told as the error it is.
    pub fn lay(self, line: &[u8], out: &mut Vec<u8>) {
        match serde_json::from_slice::<BuildEvent>(line) {
            Ok(event) => self.event(&event, out),
            Err(e) => error(
                out,
                &format!("the engine sent a build event that is not one: {e}"),
            ),
        }
    }

    fn event(self, event: &BuildEvent, out: &mut Vec<u8>) {
        let text = event.text.as_str();
        match (event.kind, self.quiet) {
            (BuildEventKind::Step, false) => stream(out, &format!("{text}\n")),
            // podman (pkg/api/handlers/compat/images_build.go): the
            // standard output of the RUNs streams with q too
            (BuildEventKind::Output, _) if event.stream == BuildStream::Stdout => stream(out, text),
            (BuildEventKind::Output, false) if text.ends_with('\n') => stream(out, text),
            (BuildEventKind::Output, false) => stream(out, &format!("{text}\n")),
            (BuildEventKind::Complete, false) if self.docker => {
                out.extend_from_slice(b"{\"aux\":{\"ID\":");
                string(out, &crate::id_with_algorithm(text));
                out.extend_from_slice(b"}}\n");
                let short = text.get(..12).unwrap_or(text);
                stream(out, &format!("Successfully built {short}\n"));
                for t in &event.tags {
                    stream(out, &format!("Successfully tagged {t}\n"));
                }
            }
            // (the last line is the id, as buildah says it on its standard
            // output: podman's quiet build of the Docker route too)
            (BuildEventKind::Complete, _) => stream(out, &format!("{text}\n")),
            (BuildEventKind::Error, _) => error(out, text),
            _ => {}
        }
    }
}

/// The line of a failed build.
fn error(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(b"{\"error\":");
    string(out, text);
    out.extend_from_slice(b",\"errorDetail\":{\"message\":");
    string(out, text);
    out.extend_from_slice(b"}}\n");
}

// (the lines are written by hand, not as maps)

/// `s` as a JSON string.
fn string(out: &mut Vec<u8>, s: &str) {
    let _ = serde_json::to_writer(&mut *out, s);
}

/// The line `{"stream":S}`.
fn stream(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(b"{\"stream\":");
    string(out, s);
    out.extend_from_slice(b"}\n");
}

#[cfg(test)]
mod tests {
    use super::BuildLines;

    /// A line that is no event is told to the client as an error, not
    /// dropped.
    #[test]
    fn a_line_that_is_no_event_is_an_error() {
        let lines = BuildLines {
            quiet: false,
            docker: false,
        };
        for bad in ["not json", r#"{"kind":"nothing"}"#] {
            let mut out = Vec::new();
            lines.lay(bad.as_bytes(), &mut out);
            let told = String::from_utf8(out).unwrap();
            assert!(
                told.starts_with("{\"error\":\"the engine sent a build event"),
                "{told}"
            );
        }
    }

    fn lay(lines: BuildLines, events: &[&str]) -> String {
        let mut out = Vec::new();
        for e in events {
            lines.lay(format!("{e}\n").as_bytes(), &mut out);
        }
        String::from_utf8(out).unwrap()
    }

    const EVENTS: &[&str] = &[
        r#"{"kind":"started","step":2,"stream":"step"}"#,
        r#"{"kind":"step","step":1,"text":"STEP 1/2: FROM x","stream":"step"}"#,
        r#"{"kind":"output","step":1,"text":"said","stream":"step"}"#,
        r#"{"kind":"output","step":1,"text":"out\n","stream":"stdout"}"#,
        r#"{"kind":"output","step":1,"text":"part","stream":"stdout"}"#,
        r#"{"kind":"output","step":1,"text":"err","stream":"stderr"}"#,
        r#"{"kind":"output","text":"pulled\n","stream":"report"}"#,
        r#"{"kind":"progress","stream":"step","progress":{"layer":"sha256:aa"}}"#,
        r#"{"kind":"credentials","stream":"step","ask":"1","scopes":["r.io"]}"#,
        r#"{"kind":"complete","text":"abcdef0123456789","stream":"step","tags":["localhost/t:1","localhost/t:2"]}"#,
    ];

    /// podman's lines, Docker's, and the quiet ones: the output of a RUN
    /// is told with `quiet` too (as it comes), the end differs by client,
    /// the start, the progress and the questions are not told.
    #[test]
    fn the_events_of_a_build_are_laid_out_as_each_client_expects() {
        let libpod = BuildLines {
            quiet: false,
            docker: false,
        };
        assert_eq!(
            lay(libpod, EVENTS),
            "{\"stream\":\"STEP 1/2: FROM x\\n\"}\n{\"stream\":\"said\\n\"}\n\
             {\"stream\":\"out\\n\"}\n{\"stream\":\"part\"}\n{\"stream\":\"err\\n\"}\n\
             {\"stream\":\"pulled\\n\"}\n{\"stream\":\"abcdef0123456789\\n\"}\n"
        );
        let docker = BuildLines {
            quiet: false,
            docker: true,
        };
        let out = lay(docker, EVENTS);
        assert!(
            out.ends_with(
                "{\"stream\":\"pulled\\n\"}\n{\"aux\":{\"ID\":\"sha256:abcdef0123456789\"}}\n\
                 {\"stream\":\"Successfully built abcdef012345\\n\"}\n\
                 {\"stream\":\"Successfully tagged localhost/t:1\\n\"}\n\
                 {\"stream\":\"Successfully tagged localhost/t:2\\n\"}\n"
            ),
            "{out}"
        );
        let quiet = BuildLines {
            quiet: true,
            docker: false,
        };
        assert_eq!(
            lay(quiet, EVENTS),
            "{\"stream\":\"out\\n\"}\n{\"stream\":\"part\"}\n{\"stream\":\"abcdef0123456789\\n\"}\n"
        );
        let docker_quiet = BuildLines {
            quiet: true,
            docker: true,
        };
        assert!(lay(docker_quiet, EVENTS).ends_with("{\"stream\":\"abcdef0123456789\\n\"}\n"));
        let failed = lay(libpod, &[r#"{"kind":"error","text":"a \"b\"\n"}"#]);
        assert_eq!(
            failed,
            "{\"error\":\"a \\\"b\\\"\\n\",\"errorDetail\":{\"message\":\"a \\\"b\\\"\\n\"}}\n"
        );
    }
}
