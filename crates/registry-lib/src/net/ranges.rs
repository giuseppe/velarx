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

/// Fetch `ranges` (ascending, disjoint, half open) of a blob and hand
/// the bytes to `sink` as they arrive.
pub async fn fetch_ranges(
    client: &RegistryClient,
    target: &Target,
    digest: &Digest,
    ranges: &[Range<u64>],
    sink: &mut PieceSink<'_>,
) -> Result<(), RangesError> {
    if ranges.is_empty() || ranges.iter().any(|r| r.start >= r.end) {
        return Err(bad("invalid byte ranges"));
    }
    if ranges.windows(2).any(|w| w[0].end > w[1].start) {
        return Err(bad("byte ranges are not ascending and disjoint"));
    }
    let header = range_header(ranges);
    let resp = client.get_blob(target, digest, Some(&header)).await?;
    let status = resp.status();
    if status == StatusCode::BAD_REQUEST || status == StatusCode::RANGE_NOT_SATISFIABLE {
        return Err(RangesError::Rejected(status.as_u16()));
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
            // The server ignores Range: cut what was asked from the
            // whole blob, and stop at the end of the last range.  The
            // next requests are planned for it.
            ignores_ranges(&target.endpoint.host);
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
