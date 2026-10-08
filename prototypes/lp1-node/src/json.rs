//! Strict JSON (RFC 8259) for RPC requests: UTF-8 checked first, duplicate object keys rejected at
//! any depth (compared after unescaping), container nesting <= 16, lone surrogates rejected,
//! numbers kept as their exact lexeme (never converted through floating point).

pub const MAX_DEPTH: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JVal {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<JVal>),
    Obj(Vec<(String, JVal)>),
}

impl JVal {
    pub fn get(&self, key: &str) -> Option<&JVal> {
        match self {
            JVal::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonError {
    Utf8,
    Syntax,
    DuplicateKey,
    Depth,
}

impl JsonError {
    pub fn reason(&self) -> &'static str {
        match self {
            JsonError::Utf8 => "utf8",
            JsonError::Syntax => "json",
            JsonError::DuplicateKey => "duplicateKey",
            JsonError::Depth => "depth",
        }
    }
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> P<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn eat(&mut self, c: u8) -> Result<(), JsonError> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(JsonError::Syntax)
        }
    }

    fn value(&mut self, depth: usize) -> Result<JVal, JsonError> {
        self.ws();
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => Ok(JVal::Str(self.string()?)),
            Some(b't') => self.lit(b"true", JVal::Bool(true)),
            Some(b'f') => self.lit(b"false", JVal::Bool(false)),
            Some(b'n') => self.lit(b"null", JVal::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(JsonError::Syntax),
        }
    }

    fn lit(&mut self, word: &[u8], v: JVal) -> Result<JVal, JsonError> {
        if self.b[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(JsonError::Syntax)
        }
    }

    fn object(&mut self, depth: usize) -> Result<JVal, JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::Depth);
        }
        self.eat(b'{')?;
        let mut members: Vec<(String, JVal)> = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(JVal::Obj(members));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(JsonError::Syntax);
            }
            let k = self.string()?;
            self.ws();
            self.eat(b':')?;
            let v = self.value(depth)?;
            if members.iter().any(|(x, _)| *x == k) {
                return Err(JsonError::DuplicateKey);
            }
            members.push((k, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(JVal::Obj(members));
                }
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<JVal, JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::Depth);
        }
        self.eat(b'[')?;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(JVal::Arr(items));
        }
        loop {
            items.push(self.value(depth)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(JVal::Arr(items));
                }
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        if self.i + 4 > self.b.len() {
            return Err(JsonError::Syntax);
        }
        let mut v = 0u32;
        for k in 0..4 {
            let c = self.b[self.i + k];
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(JsonError::Syntax),
            };
            v = v * 16 + d as u32;
        }
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.eat(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = match self.peek() {
                Some(c) => c,
                None => return Err(JsonError::Syntax),
            };
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek().ok_or(JsonError::Syntax)?;
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xd800..0xdc00).contains(&hi) {
                                if self.peek() != Some(b'\\') || self.b.get(self.i + 1) != Some(&b'u') {
                                    return Err(JsonError::Syntax);
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&lo) {
                                    return Err(JsonError::Syntax);
                                }
                                0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                            } else if (0xdc00..0xe000).contains(&hi) {
                                return Err(JsonError::Syntax);
                            } else {
                                hi
                            };
                            let ch = std::char::from_u32(cp).ok_or(JsonError::Syntax)?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(JsonError::Syntax),
                    }
                }
                c if c < 0x20 => return Err(JsonError::Syntax),
                c => out.push(c),
            }
        }
        String::from_utf8(out).map_err(|_| JsonError::Utf8)
    }

    fn digits(&mut self) -> usize {
        let s = self.i;
        while self.i < self.b.len() && self.b[self.i].is_ascii_digit() {
            self.i += 1;
        }
        self.i - s
    }

    fn number(&mut self) -> Result<JVal, JsonError> {
        let s = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(c) if c.is_ascii_digit() => {
                self.digits();
            }
            _ => return Err(JsonError::Syntax),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return Err(JsonError::Syntax);
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err(JsonError::Syntax);
            }
        }
        let lex = std::str::from_utf8(&self.b[s..self.i]).map_err(|_| JsonError::Syntax)?;
        Ok(JVal::Num(lex.to_string()))
    }
}

pub fn parse(bytes: &[u8]) -> Result<JVal, JsonError> {
    if std::str::from_utf8(bytes).is_err() {
        return Err(JsonError::Utf8);
    }
    let mut p = P { b: bytes, i: 0 };
    let v = p.value(0)?;
    p.ws();
    if p.i != bytes.len() {
        return Err(JsonError::Syntax);
    }
    Ok(v)
}

/// Exact value semantics for a JSON number lexeme: Some(v) iff the number's exact decimal value is
/// an integer in 0..=2^32-1 ("5", "5.0", "5e0", "50e-1", "-0" all give 5 or 0). Never uses floats.
pub fn integral_u32(lex: &str) -> Option<u32> {
    let (neg, body) = match lex.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, lex),
    };
    let (mant, exp) = match body.find(|c: char| c == 'e' || c == 'E') {
        Some(k) => (&body[..k], &body[k + 1..]),
        None => (body, ""),
    };
    let (int_part, frac_part) = match mant.split_once('.') {
        Some((a, b)) => (a, b),
        None => (mant, ""),
    };
    let exp_digits = exp.strip_prefix(|c: char| c == '+' || c == '-').unwrap_or(exp);
    if int_part.is_empty()
        || !int_part.bytes().all(|c| c.is_ascii_digit())
        || !frac_part.bytes().all(|c| c.is_ascii_digit())
        || !exp_digits.bytes().all(|c| c.is_ascii_digit())
        || (body.len() > mant.len() && exp_digits.is_empty())
    {
        return None;
    }
    let mut digits: Vec<u8> = int_part.bytes().chain(frac_part.bytes()).map(|c| c - b'0').collect();
    // Exponent, clamped: anything beyond +-10^6 is decided by sign alone below.
    let e: i64 = if exp.is_empty() {
        0
    } else {
        let (es, ed) = match exp.as_bytes()[0] {
            b'+' => (1i64, &exp[1..]),
            b'-' => (-1i64, &exp[1..]),
            _ => (1i64, exp),
        };
        let ed = ed.trim_start_matches('0');
        if ed.len() > 7 {
            es * 10_000_000
        } else if ed.is_empty() {
            0
        } else {
            es * ed.parse::<i64>().ok()?
        }
    };
    let mut scale = e - frac_part.len() as i64;
    while digits.first() == Some(&0) {
        digits.remove(0);
    }
    if digits.is_empty() {
        return Some(0);
    }
    if neg {
        return None;
    }
    while digits.last() == Some(&0) {
        digits.pop();
        scale += 1;
    }
    if scale < 0 {
        return None;
    }
    if digits.len() as i64 + scale > 10 {
        return None;
    }
    let mut v: u64 = 0;
    for d in &digits {
        v = v * 10 + *d as u64;
    }
    for _ in 0..scale {
        v *= 10;
    }
    if v > u32::MAX as u64 {
        None
    } else {
        Some(v as u32)
    }
}

/// JSON string literal for output.
pub fn quote(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for ch in s.chars() {
        match ch {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_and_rejects() {
        assert!(parse(br#"{"a":[1,2,{"b":null}],"c":"é😀"}"#).is_ok());
        assert_eq!(parse(br#"{"a":1,"a":2}"#), Err(JsonError::DuplicateKey));
        assert_eq!(parse(br#"{"x":{"a":1,"a":2}}"#), Err(JsonError::DuplicateKey));
        assert_eq!(parse(br#"[{"k":[{"a":0,"a":0}]}]"#), Err(JsonError::DuplicateKey));
        assert_eq!(parse(b"{\"a\":\"\xff\"}"), Err(JsonError::Utf8));
        assert_eq!(parse(br#"{"a":01}"#), Err(JsonError::Syntax));
        assert_eq!(parse(br#"{"a":1.}"#), Err(JsonError::Syntax));
        assert_eq!(parse(br#"{"a":+1}"#), Err(JsonError::Syntax));
        assert_eq!(parse(br#"{"a":NaN}"#), Err(JsonError::Syntax));
        assert_eq!(parse(br#"{"a":"\ud800"}"#), Err(JsonError::Syntax));
        assert_eq!(parse(br#"{"a":"\udc00"}"#), Err(JsonError::Syntax));
        assert_eq!(parse(b"{\"a\":\"\x01\"}"), Err(JsonError::Syntax));
        assert_eq!(parse(br#"{} x"#), Err(JsonError::Syntax));
        assert_eq!(parse(br#"{"a":1,}"#), Err(JsonError::Syntax));
        assert_eq!(parse(b""), Err(JsonError::Syntax));
    }

    #[test]
    fn depth_boundary() {
        let ok = format!("{}{}", "[".repeat(16), "]".repeat(16));
        assert!(parse(ok.as_bytes()).is_ok());
        let deep = format!("{}{}", "[".repeat(17), "]".repeat(17));
        assert_eq!(parse(deep.as_bytes()), Err(JsonError::Depth));
        let huge = "[".repeat(100_000);
        assert_eq!(parse(huge.as_bytes()), Err(JsonError::Depth));
    }

    #[test]
    fn integral_semantics() {
        for (lex, want) in [
            ("0", Some(0)),
            ("-0", Some(0)),
            ("-0.0e5", Some(0)),
            ("7", Some(7)),
            ("7.0", Some(7)),
            ("7e0", Some(7)),
            ("70e-1", Some(7)),
            ("0.7e1", Some(7)),
            ("4294967295", Some(u32::MAX)),
            ("4294967295.000", Some(u32::MAX)),
            ("4294967296", None),
            ("42949672950e-1", Some(u32::MAX)),
            ("-1", None),
            ("1.5", None),
            ("1e-400", None),
            ("1e400", None),
            ("1e99999999999", None),
            ("0e99999999999", Some(0)),
        ] {
            assert_eq!(integral_u32(lex), want, "{lex}");
        }
    }
}
