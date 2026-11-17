// SPDX-License-Identifier: Apache-2.0
//! The keep set of a collection ([`Keep`]) as the lines of a file: one JSON
//! record per layer, chain id, image, container and pull, and one for the grace period.
//!
//! A message of a remote driver is bounded (`Limits::message`, 1 MiB), and the
//! keep set is not: a store of 4,200 layers does not fit one message, and
//! every chain prefix of every image is a layer more.  So `Collect` does not
//! carry the set; it carries the **length** of a sealed memfd that holds these
//! lines (as `Index` carries its table of contents), which the driver reads
//! as a stream: no document has to be built or parsed whole.

use crate::Keep;
use std::io::{BufRead, Write};
use std::time::Duration;
use velarx_db::LayerKey;
use velarx_types::digest::Digest;

impl Keep {
    /// The records of the set, one JSON object per line, the grace period
    /// first.
    pub fn write_lines(&self, out: &mut dyn Write) -> std::io::Result<()> {
        let line = |out: &mut dyn Write, kind: &str, value: serde_json::Value| {
            serde_json::to_writer(&mut *out, &serde_json::json!({ kind: value }))?;
            out.write_all(b"\n")
        };
        line(out, "grace_secs", self.grace.as_secs().into())?;
        for l in &self.layers {
            line(out, "layer", l.to_string().into())?;
        }
        for c in &self.chains {
            line(out, "chain", c.to_string().into())?;
        }
        for i in &self.images {
            line(out, "image", i.as_str().into())?;
        }
        for c in &self.containers {
            line(out, "container", c.as_str().into())?;
        }
        for p in &self.pulls {
            line(out, "pull", p.as_str().into())?;
        }
        Ok(())
    }

    /// The records of [`Keep::write_lines`], a line at a time.  A record this
    /// build does not know is an error (the engine writes the lines, and the
    /// version of the interface is the same on both sides).
    pub fn read_lines(input: &mut dyn BufRead) -> Result<Keep, String> {
        let mut keep = Keep::default();
        let mut line = String::new();
        let mut n = 0usize;
        loop {
            line.clear();
            n += 1;
            if input.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
                return Ok(keep);
            }
            let record: serde_json::Map<String, serde_json::Value> =
                serde_json::from_str(&line).map_err(|e| format!("line {n}: {e}"))?;
            let [(kind, value)] = record.iter().collect::<Vec<_>>()[..] else {
                return Err(format!("line {n}: one record is one key"));
            };
            let text = || {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("line {n}: {kind} is a string"))
            };
            match kind.as_str() {
                "grace_secs" => {
                    keep.grace = Duration::from_secs(
                        value
                            .as_u64()
                            .ok_or_else(|| format!("line {n}: grace_secs is a number"))?,
                    )
                }
                "layer" => keep.layers.push(
                    LayerKey::parse(&text()?)
                        .ok_or_else(|| format!("line {n}: not a layer key"))?,
                ),
                "chain" => keep.chains.push(
                    text()?
                        .parse::<Digest>()
                        .map_err(|e| format!("line {n}: not a chain id: {e}"))?,
                ),
                "image" => keep.images.push(text()?),
                "container" => keep.containers.push(text()?),
                "pull" => keep.pulls.push(text()?),
                other => return Err(format!("line {n}: the record {other:?} is not known")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u32) -> LayerKey {
        LayerKey::Whole(format!("sha256:{n:064x}").parse().unwrap())
    }

    fn chain(n: u32) -> Digest {
        format!("sha256:{:064x}", u64::from(n) + (1 << 40))
            .parse()
            .unwrap()
    }

    /// A store that is too big for a message is a file of lines that is read
    /// back whole: 20,000 layers of images, with their images, containers and
    /// pulls, are more than the 1 MiB of a message.
    #[test]
    fn a_keep_set_beyond_a_message_goes_through_lines() {
        let keep = Keep {
            layers: (0..20_000).map(key).collect(),
            chains: (0..20_000).map(chain).collect(),
            images: (0..3_000).map(|n| format!("{n:064x}")).collect(),
            containers: (0..2_000).map(|n| format!("{n:064x}")).collect(),
            pulls: (0..100).map(|n| format!("pull-{n}")).collect(),
            grace: Duration::from_secs(86_400),
        };
        // as the one JSON document a message would be
        let document = serde_json::to_vec(&serde_json::json!({
            "layers": keep.layers.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "chains": keep.chains.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "images": keep.images,
            "containers": keep.containers,
            "pulls": keep.pulls,
        }))
        .unwrap();
        assert!(
            document.len() > crate::Limits::V1.message,
            "{} bytes",
            document.len()
        );
        let mut lines = Vec::new();
        keep.write_lines(&mut lines).unwrap();
        let back = Keep::read_lines(&mut lines.as_slice()).unwrap();
        assert_eq!(back.layers, keep.layers);
        assert_eq!(back.chains, keep.chains);
        assert_eq!(back.images, keep.images);
        assert_eq!(back.containers, keep.containers);
        assert_eq!(back.pulls, keep.pulls);
        assert_eq!(back.grace, keep.grace);
        // no line is more than a record
        assert!(lines.split(|b| *b == b'\n').all(|l| l.len() < 200));
    }

    #[test]
    fn a_line_that_is_no_record_is_an_error_with_its_number() {
        for (text, why) in [
            ("{\"layer\":\"nope\"}\n", "line 1: not a layer key"),
            ("{\"chain\":\"nope\"}\n", "line 1: not a chain id"),
            (
                "{\"grace_secs\":1}\n{\"image\":3}\n",
                "line 2: image is a string",
            ),
            ("{\"a\":1,\"b\":2}\n", "line 1: one record is one key"),
            (
                "{\"weird\":\"x\"}\n",
                "line 1: the record \"weird\" is not known",
            ),
            ("not json\n", "line 1: "),
        ] {
            let e = Keep::read_lines(&mut text.as_bytes()).unwrap_err();
            assert!(e.starts_with(why), "{e}");
        }
        assert!(Keep::read_lines(&mut &b""[..]).unwrap().layers.is_empty());
    }
}
