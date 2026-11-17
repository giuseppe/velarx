// SPDX-License-Identifier: Apache-2.0
//! The layers of the test images of lazy pulls (`tools/make-lazy-fixtures`
//! runs this).
//!
//!   lazy_fixture rewrite SRC_OCI DST_OCI MODE
//!   lazy_fixture digest FILE...
//!
//! `rewrite` reads the image of the OCI layout directory SRC_OCI (one image,
//! as `skopeo copy --override-os linux docker://... oci:SRC_OCI` makes it) and
//! writes the same image to the layout DST_OCI with every layer written again
//! by the code the engine pushes layers with, from the same tar stream (the
//! diff ids and the configuration are unchanged).  MODE:
//!
//!   verity   zstd:chunked; the table of contents gives, for each regular
//!            file with content, its sha256 `digest` and its fs-verity digest
//!            in `fsverity` (`sha256-12:HEX`: sha256, blocks of 2^12 bytes,
//!            no salt, as the kernel measures it)
//!   sha256   zstd:chunked; the table of contents gives only `digest`
//!   gzip     gzip, no table of contents
//!
//! `digest` prints the fs-verity digest (`sha256:HEX`, as `fsverity measure`
//! does) of each file.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use velarx_content::layer::writer::{write_layer, write_layer_sha256_keyed, Compression, Written};
use velarx_types::digest::{Algorithm, Digest};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn blob_path(dir: &Path, digest: &str) -> Res<PathBuf> {
    let (alg, hex) = digest
        .split_once(':')
        .ok_or("a digest without an algorithm")?;
    if alg != "sha256" || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("not a sha256 digest: {digest}").into());
    }
    Ok(dir.join("blobs").join(alg).join(hex))
}

fn read_json(path: &Path) -> Res<Value> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

/// The tar stream of a layer blob, whatever its compression.
fn open_tar(path: &Path) -> Res<Box<dyn Read>> {
    let mut file = std::fs::File::open(path)?;
    let mut magic = [0u8; 4];
    let n = file.read(&mut magic)?;
    std::io::Seek::rewind(&mut file)?;
    Ok(match &magic[..n] {
        [0x1f, 0x8b, ..] => Box::new(flate2::read::MultiGzDecoder::new(file)),
        [0x28, 0xb5, 0x2f, 0xfd] => Box::new(zstd::stream::read::Decoder::new(file)?),
        _ => Box::new(file),
    })
}

fn put_blob(dst: &Path, data: &[u8]) -> Res<Digest> {
    let digest = Digest::of(Algorithm::Sha256, data);
    let path = blob_path(dst, &digest.to_string())?;
    std::fs::write(path, data)?;
    Ok(digest)
}

fn rewrite(src: &Path, dst: &Path, mode: &str) -> Res<()> {
    std::fs::create_dir_all(dst.join("blobs/sha256"))?;
    let index = read_json(&src.join("index.json"))?;
    let manifests = index["manifests"].as_array().ok_or("no manifests")?;
    if manifests.len() != 1 {
        return Err("the source layout must hold exactly one image".into());
    }
    let manifest_digest = manifests[0]["digest"].as_str().ok_or("no digest")?;
    let mut manifest = read_json(&blob_path(src, manifest_digest)?)?;
    let config = manifest["config"].clone();
    if manifest["mediaType"] != "application/vnd.oci.image.manifest.v1+json" {
        return Err("the source image is not an OCI image (copy it to an oci: layout)".into());
    }
    std::fs::copy(
        blob_path(src, config["digest"].as_str().ok_or("no config")?)?,
        blob_path(dst, config["digest"].as_str().ok_or("no config")?)?,
    )?;
    let layers = manifest["layers"].as_array_mut().ok_or("no layers")?;
    for layer in layers {
        let old = blob_path(src, layer["digest"].as_str().ok_or("no layer digest")?)?;
        let tmp = dst.join("blobs/sha256/.writing");
        let mut out = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
        let tar = open_tar(&old)?;
        let alg = Algorithm::Sha256;
        let written: Written = match mode {
            "verity" => write_layer(tar, alg, Compression::ZstdChunked, &mut out)?,
            "sha256" => write_layer_sha256_keyed(tar, alg, Compression::ZstdChunked, &mut out)?,
            "gzip" => write_layer(tar, alg, Compression::Gzip, &mut out)?,
            _ => return Err(format!("unknown mode {mode} (verity, sha256, gzip)").into()),
        };
        out.flush()?;
        drop(out);
        std::fs::rename(&tmp, blob_path(dst, &written.digest.to_string())?)?;
        let mut d = json!({
            "mediaType": written.media_type,
            "digest": written.digest.to_string(),
            "size": written.size,
        });
        if !written.annotations.is_empty() {
            d["annotations"] = json!(written.annotations);
        }
        *layer = d;
    }
    let digest = put_blob(dst, &serde_json::to_vec(&manifest)?)?;
    let size = serde_json::to_vec(&manifest)?.len();
    std::fs::write(
        dst.join("index.json"),
        serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": digest.to_string(),
                "size": size,
            }],
        }))?,
    )?;
    std::fs::write(dst.join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#)?;
    Ok(())
}

fn main() -> Res<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["rewrite", src, dst, mode] => rewrite(Path::new(src), Path::new(dst), mode),
        ["digest", ..] if args.len() > 1 => {
            for path in &args[1..] {
                let file = std::fs::File::open(path)?;
                let digest = velarx_storage::fsverity_digest_file(Algorithm::Sha256, &file)?;
                println!("sha256:{}  {path}", Digest::parse_fsverity(&digest)?.hex());
            }
            Ok(())
        }
        _ => Err(
            "usage: lazy_fixture rewrite SRC_OCI DST_OCI verity|sha256|gzip | digest FILE..."
                .into(),
        ),
    }
}
