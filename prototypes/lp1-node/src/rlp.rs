//! Strict canonical RLP (same acceptance as m1-draft-0.2/tools/rlp_strict.py) with an explicit
//! nesting bound. Decoding borrows from the input; every item keeps its exact raw encoding.

pub const MAX_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrKind {
    Truncated,
    NonCanonical,
    Trailing,
    TooDeep,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RlpError {
    pub kind: ErrKind,
    pub detail: &'static str,
}

impl RlpError {
    pub fn code(&self) -> &'static str {
        match self.kind {
            ErrKind::Truncated => "decode.truncated",
            ErrKind::NonCanonical => "decode.noncanonical",
            ErrKind::Trailing => "decode.trailing",
            ErrKind::TooDeep => "decode.depth",
        }
    }
}

fn err(kind: ErrKind, detail: &'static str) -> RlpError {
    RlpError { kind, detail }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind<'a> {
    Bytes(&'a [u8]),
    List(Vec<Item<'a>>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item<'a> {
    /// The exact bytes of this item's encoding (prefix included).
    pub raw: &'a [u8],
    pub kind: Kind<'a>,
}

impl<'a> Item<'a> {
    pub fn bytes(&self) -> Option<&'a [u8]> {
        match self.kind {
            Kind::Bytes(b) => Some(b),
            Kind::List(_) => None,
        }
    }

    pub fn list(&self) -> Option<&[Item<'a>]> {
        match &self.kind {
            Kind::List(v) => Some(v),
            Kind::Bytes(_) => None,
        }
    }
}

fn be_len(b: &[u8]) -> Option<usize> {
    if b.len() > 8 {
        return None;
    }
    let mut n: u64 = 0;
    for x in b {
        n = (n << 8) | *x as u64;
    }
    if n > usize::MAX as u64 {
        None
    } else {
        Some(n as usize)
    }
}

/// Reads the prefix at `i` within `[i, end)`; returns (is_list, payload_start, payload_len).
fn prefix(b: &[u8], i: usize, end: usize) -> Result<(bool, usize, usize), RlpError> {
    if i >= end {
        return Err(err(ErrKind::Truncated, "offset"));
    }
    let p = b[i];
    if p < 0x80 {
        return Ok((false, i, 1));
    }
    let (list, short_base, long_base) = if p < 0xc0 { (false, 0x80u8, 0xb7u8) } else { (true, 0xc0u8, 0xf7u8) };
    if p <= long_base {
        let n = (p - short_base) as usize;
        if n > end - (i + 1) {
            return Err(err(ErrKind::Truncated, if list { "list body" } else { "string body" }));
        }
        if !list && n == 1 && b[i + 1] < 0x80 {
            return Err(err(ErrKind::NonCanonical, "single byte wrapped"));
        }
        return Ok((list, i + 1, n));
    }
    let ll = (p - long_base) as usize;
    if ll > end - (i + 1) {
        return Err(err(ErrKind::Truncated, "length of length"));
    }
    if b[i + 1] == 0 {
        return Err(err(ErrKind::NonCanonical, "leading zero in length"));
    }
    let n = match be_len(&b[i + 1..i + 1 + ll]) {
        Some(n) => n,
        None => return Err(err(ErrKind::Truncated, "length of length")),
    };
    if n < 56 {
        return Err(err(ErrKind::NonCanonical, if list { "long form for short list" } else { "long form for short string" }));
    }
    let s = i + 1 + ll;
    if n > end - s {
        return Err(err(ErrKind::Truncated, if list { "list body" } else { "string body" }));
    }
    Ok((list, s, n))
}

fn item<'a>(b: &'a [u8], i: usize, end: usize, depth: usize, max_depth: usize) -> Result<(Item<'a>, usize), RlpError> {
    let (list, s, n) = prefix(b, i, end)?;
    let stop = s + n;
    if !list {
        return Ok((Item { raw: &b[i..stop], kind: Kind::Bytes(&b[s..stop]) }, stop));
    }
    if depth + 1 > max_depth {
        return Err(err(ErrKind::TooDeep, "nesting"));
    }
    let mut children = Vec::new();
    let mut j = s;
    while j < stop {
        let (c, next) = item(b, j, stop, depth + 1, max_depth)?;
        children.push(c);
        j = next;
    }
    Ok((Item { raw: &b[i..stop], kind: Kind::List(children) }, stop))
}

/// Decodes exactly one item spanning all of `b`; at most `max_depth` nested lists.
pub fn decode_with_depth(b: &[u8], max_depth: usize) -> Result<Item<'_>, RlpError> {
    let (it, j) = item(b, 0, b.len(), 0, max_depth)?;
    if j != b.len() {
        return Err(err(ErrKind::Trailing, "trailing bytes"));
    }
    Ok(it)
}

pub fn decode(b: &[u8]) -> Result<Item<'_>, RlpError> {
    decode_with_depth(b, MAX_DEPTH)
}

fn push_prefix(out: &mut Vec<u8>, n: usize, short_base: u8) {
    if n < 56 {
        out.push(short_base + n as u8);
    } else {
        let be = (n as u64).to_be_bytes();
        let first = be.iter().position(|x| *x != 0).unwrap_or(7);
        out.push(short_base + 55 + (8 - first) as u8);
        out.extend_from_slice(&be[first..]);
    }
}

pub fn encode_bytes(b: &[u8], out: &mut Vec<u8>) {
    if b.len() == 1 && b[0] < 0x80 {
        out.push(b[0]);
    } else {
        push_prefix(out, b.len(), 0x80);
        out.extend_from_slice(b);
    }
}

/// Wraps an already concatenated sequence of item encodings in a list prefix.
pub fn encode_list_payload(payload: &[u8], out: &mut Vec<u8>) {
    push_prefix(out, payload.len(), 0xc0);
    out.extend_from_slice(payload);
}

/// Encodes from the decoded structure (not from `raw`); used to prove exact re-encoding.
pub fn encode(it: &Item<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(it, &mut out);
    out
}

fn encode_into(it: &Item<'_>, out: &mut Vec<u8>) {
    match &it.kind {
        Kind::Bytes(b) => encode_bytes(b, out),
        Kind::List(children) => {
            let mut payload = Vec::new();
            for c in children {
                encode_into(c, &mut payload);
            }
            encode_list_payload(&payload, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(b: &[u8]) -> Option<ErrKind> {
        decode(b).err().map(|e| e.kind)
    }

    #[test]
    fn canonical_round_trips() {
        for hex in ["80", "00", "7f", "8180", "c0", "c3010203", "c7c0c1c0c3c0c1c0"] {
            let b = crate::hex::decode(hex).unwrap();
            let it = decode(&b).unwrap();
            assert_eq!(encode(&it), b, "{hex}");
            assert_eq!(it.raw, &b[..]);
        }
        let long = vec![0x55u8; 56];
        let mut enc = Vec::new();
        encode_bytes(&long, &mut enc);
        assert_eq!(&enc[..2], &[0xb8, 56]);
        assert_eq!(decode(&enc).unwrap().bytes().unwrap(), &long[..]);
        let big = vec![1u8; 300];
        let mut enc = Vec::new();
        encode_bytes(&big, &mut enc);
        assert_eq!(&enc[..3], &[0xb9, 1, 44]);
        assert_eq!(encode(&decode(&enc).unwrap()), enc);
    }

    #[test]
    fn strictness_boundaries() {
        assert_eq!(kind(&[]), Some(ErrKind::Truncated));
        assert_eq!(kind(&[0x81, 0x00]), Some(ErrKind::NonCanonical)); // single byte wrapped
        assert_eq!(kind(&[0x81, 0x7f]), Some(ErrKind::NonCanonical));
        assert!(decode(&[0x81, 0x80]).is_ok());
        assert_eq!(kind(&[0xb8, 0x05, 1, 2, 3, 4, 5]), Some(ErrKind::NonCanonical)); // long form, n < 56
        assert_eq!(kind(&[0xb9, 0x00, 0x38]), Some(ErrKind::NonCanonical)); // leading zero in length
        assert_eq!(kind(&[0xb8]), Some(ErrKind::Truncated));
        assert_eq!(kind(&[0x83, 1, 2]), Some(ErrKind::Truncated));
        assert_eq!(kind(&[0x80, 0x80]), Some(ErrKind::Trailing));
        assert_eq!(kind(&[0xc2, 0x83, 0x01]), Some(ErrKind::Truncated)); // item crosses list end
        assert_eq!(kind(&[0xf8, 0x01, 0x80]), Some(ErrKind::NonCanonical));
        assert_eq!(kind(&[0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), Some(ErrKind::Truncated));
    }

    #[test]
    fn depth_bound() {
        // 16 nested lists decode; 17 are rejected without recursion beyond the bound.
        let mut ok = vec![0xc0u8];
        for _ in 0..15 {
            let mut w = vec![0xc0 + ok.len() as u8];
            w.extend_from_slice(&ok);
            ok = w;
        }
        assert!(decode(&ok).is_ok());
        let mut deep = vec![0xc0 + ok.len() as u8];
        deep.extend_from_slice(&ok);
        assert_eq!(kind(&deep), Some(ErrKind::TooDeep));
        // A 2000-deep well-formed input (long-form list prefixes) is rejected at the bound, no stack growth.
        let mut v = vec![0xc0u8];
        for _ in 0..2000 {
            let mut w = Vec::with_capacity(v.len() + 4);
            encode_list_payload(&v, &mut w);
            v = w;
        }
        assert_eq!(kind(&v), Some(ErrKind::TooDeep));
        assert!(decode_with_depth(&v, 2001).is_ok());
    }
}
