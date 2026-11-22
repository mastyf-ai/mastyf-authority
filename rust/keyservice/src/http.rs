//! HTTP/1.1 request reading for the gateway: one request per call, from a byte stream.
//! Strict on purpose: GET/POST bodies by Content-Length only (no Transfer-Encoding, no duplicate
//! lengths: no request smuggling), headers <= 16 KB, bodies <= 2 MB, HTTP/1.1 only.

use std::io::Read;

pub const MAX_HEAD: usize = 16 * 1024;
pub const MAX_BODY: usize = 2 * 1024 * 1024;

#[derive(Debug, PartialEq)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub query: String,
    pub auth: Option<String>,
    pub body: Vec<u8>,
    pub close: bool,
}

#[derive(Debug, PartialEq)]
pub enum ReadErr {
    Closed,
    Bad(u16, &'static str),
}

pub fn read_request<S: Read>(s: &mut S, buf: &mut Vec<u8>) -> Result<Req, ReadErr> {
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > MAX_HEAD {
            return Err(ReadErr::Bad(431, "request headers too large"));
        }
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return Err(ReadErr::Closed),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    };
    if head_end > MAX_HEAD {
        return Err(ReadErr::Bad(431, "request headers too large"));
    }
    let mut hs = [httparse::EMPTY_HEADER; 32];
    let mut r = httparse::Request::new(&mut hs);
    match r.parse(&buf[..head_end]) {
        // the header block must end exactly where we found the blank CRLF line: a bare LF ending
        // earlier would let two parsers disagree about where the body starts (request smuggling class)
        Ok(httparse::Status::Complete(n)) if n == head_end => {}
        _ => return Err(ReadErr::Bad(400, "malformed request")),
    }
    if r.version != Some(1) {
        return Err(ReadErr::Bad(505, "HTTP/1.1 only"));
    }
    let method = r.method.unwrap_or("").to_string();
    let target = r.path.unwrap_or("").to_string();
    let (mut len, mut auth, mut close, mut seen_len) = (0usize, None, false, false);
    for h in r.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        let v = std::str::from_utf8(h.value).map_err(|_| ReadErr::Bad(400, "bad header"))?;
        match name.as_str() {
            "transfer-encoding" => return Err(ReadErr::Bad(411, "chunked bodies not accepted")),
            "content-length" => {
                if seen_len {
                    return Err(ReadErr::Bad(400, "duplicate content-length"));
                }
                seen_len = true;
                len = v.trim().parse().map_err(|_| ReadErr::Bad(400, "bad content-length"))?;
            }
            "authorization" => auth = Some(v.to_string()),
            "connection" => close = v.eq_ignore_ascii_case("close"),
            _ => {}
        }
    }
    if len > MAX_BODY {
        return Err(ReadErr::Bad(413, "body too large"));
    }
    buf.drain(..head_end);
    while buf.len() < len {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return Err(ReadErr::Closed),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    let body: Vec<u8> = buf.drain(..len).collect();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    Ok(Req { method, path, query, auth, body, close })
}
