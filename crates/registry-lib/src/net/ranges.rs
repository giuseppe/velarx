// SPDX-License-Identifier: Apache-2.0
//! The range requests on a blob: the answer is parsed and checked by
//! [`velarx_content::pull::ranges`].

use futures::future::BoxFuture;
use futures::StreamExt;
use reqwest::header::{CONTENT_RANGE, CONTENT_TYPE};
use reqwest::StatusCode;
use std::ops::Range;
use velarx_content::pull::ranges::*;
use velarx_registry::client::RegistryClient;
use velarx_registry::target::Target;
use velarx_types::digest::Digest;
use velarx_types::ImageError;

/// Callback receiving the pieces of an answer.
pub type PieceSink<'a> = dyn FnMut(Piece) -> BoxFuture<'a, Result<(), ImageError>> + Send + 'a;

fn check(ranges: &[Range<u64>]) -> Result<(), RangesError> {
    if ranges.is_empty() || ranges.iter().any(|r| r.start >= r.end) {
        return Err(bad("invalid byte ranges"));
    }
    if ranges.windows(2).any(|w| w[0].end > w[1].start) {
        return Err(bad("byte ranges are not ascending and disjoint"));
    }
    Ok(())
}

/// The largest piece `read_ranges` hands to its sink.
const PIECE: u64 = 1 << 20;

/// The bytes of `ranges` (as for [`fetch_ranges`]) of `blob`, a file that
/// has the blob, handed to `sink` as the pieces of an answer are.
pub async fn read_ranges(
    blob: &std::fs::File,
    ranges: &[Range<u64>],
    sink: &mut PieceSink<'_>,
) -> Result<(), RangesError> {
    use std::os::unix::fs::FileExt;
    check(ranges)?;
    for (range, r) in ranges.iter().enumerate() {
        let mut offset = r.start;
        while offset < r.end {
            let mut data = vec![0u8; (r.end - offset).min(PIECE) as usize];
            blob.read_exact_at(&mut data, offset)
                .map_err(|e| RangesError::Other(ImageError::Io(e)))?;
            let n = data.len() as u64;
            sink(Piece {
                range,
                offset,
                data: data.into(),
            })
            .await?;
            offset += n;
        }
    }
    Ok(())
}

/// Fetch `ranges` (ascending, disjoint, half open) of a blob and hand
/// the bytes to `sink` as they arrive.  A server that cannot give the
/// ranges (it answers 400 or 416 to a single one, or the whole blob to a
/// request that is not a prefix) is [`RangesError::WholeBlob`]: its body is
/// not read, the blob is asked whole by the caller.
pub async fn fetch_ranges(
    client: &RegistryClient,
    target: &Target,
    digest: &Digest,
    ranges: &[Range<u64>],
    sink: &mut PieceSink<'_>,
) -> Result<(), RangesError> {
    let header = range_header(ranges);
    let resp = client.get_blob(target, digest, Some(&header)).await?;
    let status = resp.status();
    if status == StatusCode::BAD_REQUEST || status == StatusCode::RANGE_NOT_SATISFIABLE {
        return Err(match ranges.len() {
            1 => RangesError::WholeBlob,
            _ => RangesError::Rejected(status.as_u16()),
        });
    }
    let headers = resp.headers().clone();
    match status {
        StatusCode::PARTIAL_CONTENT => {
            let ctype = headers
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let mut body = client.body(resp);
            if let Some(boundary) = boundary_of(ctype) {
                let mut parser = Multipart::new(&boundary, ranges);
                let mut pieces = Vec::new();
                while let Some(chunk) = body.next().await {
                    parser.push(chunk?, &mut pieces)?;
                    for p in pieces.drain(..) {
                        sink(p).await?;
                    }
                }
                if !parser.is_done() {
                    return Err(bad("the multipart answer is incomplete"));
                }
                Ok(())
            } else {
                let got = headers
                    .get(CONTENT_RANGE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(parse_content_range)
                    .ok_or_else(|| bad("a partial answer has no valid Content-Range"))?;
                if ranges.len() != 1 || got != ranges[0] {
                    return Err(bad(format!(
                        "the server sent bytes {}-{} for a request of {} ranges",
                        got.start,
                        got.end - 1,
                        ranges.len()
                    )));
                }
                let mut offset = got.start;
                while let Some(chunk) = body.next().await {
                    let chunk = chunk?;
                    let n = chunk.len() as u64;
                    if offset + n > got.end {
                        return Err(bad("the server sent more bytes than requested"));
                    }
                    sink(Piece {
                        range: 0,
                        offset,
                        data: chunk,
                    })
                    .await?;
                    offset += n;
                }
                if offset != got.end {
                    return Err(bad("the partial answer is short"));
                }
                Ok(())
            }
        }
        StatusCode::OK => {
            // A server that ignores Range gives the whole blob: a prefix is
            // cut from it, up to its end; else it is not read, the caller
            // asks for the blob once.
            if ranges.len() != 1 || ranges[0].start != 0 {
                return Err(RangesError::WholeBlob);
            }
            let mut body = client.body(resp);
            let mut pos = 0u64;
            let last_end = ranges[ranges.len() - 1].end;
            let mut current = 0;
            while let Some(chunk) = body.next().await {
                let mut chunk = chunk?;
                let chunk_end = pos + chunk.len() as u64;
                while current < ranges.len() && pos < chunk_end {
                    let r = &ranges[current];
                    if chunk_end <= r.start {
                        break;
                    }
                    let from = r.start.max(pos);
                    let to = r.end.min(chunk_end);
                    let piece = chunk.slice((from - pos) as usize..(to - pos) as usize);
                    sink(Piece {
                        range: current,
                        offset: from,
                        data: piece,
                    })
                    .await?;
                    if to == r.end {
                        current += 1;
                    } else {
                        break;
                    }
                }
                pos = chunk_end;
                chunk.clear();
                if pos >= last_end {
                    break;
                }
            }
            if current != ranges.len() {
                return Err(bad("the blob ended before the last range"));
            }
            Ok(())
        }
        other => Err(bad(format!(
            "unexpected status {other} for a range request on {digest}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// The ranges of a file come as the pieces of an answer, none longer
    /// than a piece; ranges that are not ascending are refused as for a
    /// request, and a file shorter than the blob is an error.
    #[tokio::test]
    async fn test_ranges_are_read_from_a_file() {
        let blob: Vec<u8> = (0..(PIECE as usize * 2 + 100)).map(|i| i as u8).collect();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&blob).unwrap();
        let got = std::sync::Mutex::new(Vec::new());
        let mut sink = |p: Piece| {
            got.lock()
                .unwrap()
                .push((p.range, p.offset, p.data.to_vec()));
            Box::pin(async { Ok(()) }) as BoxFuture<'_, Result<(), ImageError>>
        };
        let ranges = [3..10, PIECE..PIECE * 2 + 50];
        read_ranges(&file, &ranges, &mut sink).await.unwrap();
        let got = got.into_inner().unwrap();
        assert_eq!(
            got.iter()
                .map(|g| (g.0, g.1, g.2.len()))
                .collect::<Vec<_>>(),
            [(0, 3, 7), (1, PIECE, PIECE as usize), (1, PIECE * 2, 50)]
        );
        for (_, offset, data) in &got {
            assert_eq!(
                data[..],
                blob[*offset as usize..*offset as usize + data.len()]
            );
        }
        let mut sink =
            |_: Piece| Box::pin(async { Ok(()) }) as BoxFuture<'_, Result<(), ImageError>>;
        assert!(read_ranges(&file, &[10..20, 5..6], &mut sink)
            .await
            .is_err());
        assert!(read_ranges(&file, &[0..blob.len() as u64 + 1], &mut sink)
            .await
            .is_err());
    }
}
