//! Varied HTTP/1.1 traffic for demonstrations and screenshots of the HTTP views: several
//! clients, servers and user agents, keep-alive connections, every common method, status
//! classes 2xx to 5xx, content types, a chunked gzip body, cookies, a Basic authorization
//! (fake credentials) and a request left without response.
//!
//! The clients (192.168.1.20-22) and servers (203.0.113.10-12, 198.51.100.20) are not used by
//! the other scenarios, so their connections never collide with them when traffic is merged.

use std::fmt::Write as _;
use std::io::Write as _;

use flate2::Compression;
use flate2::write::GzEncoder;

use crate::packet::Host;
use crate::scenario::{Scenario, TcpOptions, TcpSession};
use crate::time::NS_PER_MS;

const ROUTER_MAC: [u8; 6] = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01];

fn client(last: u8) -> Host {
    Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, last], [192, 168, 1, last])
}

fn server(ip: [u8; 4]) -> Host {
    Host::v4(ROUTER_MAC, ip)
}

const FIREFOX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";
const CURL: &str = "curl/8.5.0";
const UPDATER: &str = "Updater/2.3 (compatible)";

fn request(method: &str, host: &str, target: &str, ua: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut head =
        format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n{extra}");
    if !body.is_empty() {
        let _ = write!(head, "Content-Length: {}\r\n", body.len());
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

fn response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nServer: nginx/1.24.0\r\n{headers}Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn exchange(s: &mut TcpSession<'_>, req: &[u8], resp: &[u8]) {
    s.client_send(req);
    s.scenario().advance(3 * NS_PER_MS);
    s.server_send(resp);
}

fn gzip_chunked(data: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    // Writing to a Vec cannot fail.
    let _ = enc.write_all(data);
    let gz = enc.finish().unwrap_or_default();
    let mut out = Vec::new();
    for piece in gz.chunks(512) {
        out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        out.extend_from_slice(piece);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

/// One round of varied HTTP traffic (16 transactions on 5 connections).
pub fn round(sc: &mut Scenario) {
    browser(sc);
    login(sc);
    rest_api(sc);
    updates(sc);
    unanswered(sc);
}

fn browser(sc: &mut Scenario) {
    let portal = server([203, 0, 113, 10]);
    // Browser on the portal: page (chunked gzip), style sheet, script, missing icon.
    let mut s = sc.tcp_open(client(20), portal, &TcpOptions::new(80));
    let page = format!(
        "<!doctype html><html><head><title>Portal</title></head><body>{}</body></html>",
        "<p>Internal portal news and links.</p>".repeat(60)
    );
    let mut resp = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html; charset=utf-8\r\n\
Content-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nSet-Cookie: session=7f3a9c2e41b8d605; HttpOnly\r\n\r\n"
        .to_vec();
    resp.extend_from_slice(&gzip_chunked(page.as_bytes()));
    exchange(
        &mut s,
        &request(
            "GET",
            "portal.example.test",
            "/",
            FIREFOX,
            "Accept: text/html\r\nAccept-Encoding: gzip, br\r\n",
            b"",
        ),
        &resp,
    );
    let cookie = "Cookie: session=7f3a9c2e41b8d605\r\nReferer: http://portal.example.test/\r\n";
    exchange(
        &mut s,
        &request(
            "GET",
            "portal.example.test",
            "/static/site.css",
            FIREFOX,
            cookie,
            b"",
        ),
        &response(
            "200 OK",
            "Content-Type: text/css\r\n",
            b"body { font-family: sans-serif; }\n",
        ),
    );
    exchange(
        &mut s,
        &request(
            "GET",
            "portal.example.test",
            "/static/app.js?v=3",
            FIREFOX,
            cookie,
            b"",
        ),
        &response(
            "200 OK",
            "Content-Type: application/javascript\r\n",
            b"console.log('ready');\n",
        ),
    );
    exchange(
        &mut s,
        &request(
            "GET",
            "portal.example.test",
            "/favicon.ico",
            FIREFOX,
            cookie,
            b"",
        ),
        &response(
            "404 Not Found",
            "Content-Type: text/html\r\n",
            b"<h1>Not Found</h1>",
        ),
    );
    s.close();
    sc.advance(20 * NS_PER_MS);
}

fn login(sc: &mut Scenario) {
    let portal = server([203, 0, 113, 10]);
    // Login form (fake credentials) and a redirect.
    let mut s = sc.tcp_open(client(21), portal, &TcpOptions::new(80));
    exchange(
        &mut s,
        &request(
            "POST",
            "portal.example.test",
            "/login",
            CHROME,
            "Content-Type: application/x-www-form-urlencoded\r\n",
            b"username=alice&password=demo-only",
        ),
        &response(
            "302 Found",
            "Location: /home\r\nSet-Cookie: auth=4be1c0de; Path=/\r\n",
            b"",
        ),
    );
    exchange(
        &mut s,
        &request("GET", "portal.example.test", "/old-page", CHROME, "", b""),
        &response("301 Moved Permanently", "Location: /home\r\n", b""),
    );
    s.close();
    sc.advance(20 * NS_PER_MS);
}

#[allow(clippy::too_many_lines)] // a scripted sequence of exchanges
fn rest_api(sc: &mut Scenario) {
    let api = server([203, 0, 113, 11]);
    // REST API with a Basic authorization: JSON, creation, update, deletion, options, error.
    let mut s = sc.tcp_open(client(22), api, &TcpOptions::new(8080));
    let auth = "Authorization: Basic ZGVtbzpkZW1vLW9ubHk=\r\nAccept: application/json\r\n";
    exchange(
        &mut s,
        &request(
            "GET",
            "api.example.test:8080",
            "/v1/items?page=2&limit=20",
            CURL,
            auth,
            b"",
        ),
        &response(
            "200 OK",
            "Content-Type: application/json\r\nX-Request-Id: 5d2f\r\n",
            br#"{"items":[{"id":41,"name":"router"},{"id":42,"name":"switch"}],"page":2}"#,
        ),
    );
    exchange(
        &mut s,
        &request(
            "POST",
            "api.example.test:8080",
            "/v1/items",
            CURL,
            auth,
            br#"{"name":"printer"}"#,
        ),
        &response(
            "201 Created",
            "Content-Type: application/json\r\n",
            br#"{"id":43}"#,
        ),
    );
    exchange(
        &mut s,
        &request(
            "PUT",
            "api.example.test:8080",
            "/v1/items/43",
            CURL,
            auth,
            br#"{"name":"printer-2"}"#,
        ),
        &response("204 No Content", "", b""),
    );
    exchange(
        &mut s,
        &request(
            "PATCH",
            "api.example.test:8080",
            "/v1/items/42",
            CURL,
            auth,
            br#"{"name":"core"}"#,
        ),
        &response(
            "200 OK",
            "Content-Type: application/json\r\n",
            br#"{"id":42}"#,
        ),
    );
    exchange(
        &mut s,
        &request(
            "DELETE",
            "api.example.test:8080",
            "/v1/items/40",
            CURL,
            auth,
            b"",
        ),
        &response(
            "404 Not Found",
            "Content-Type: application/json\r\n",
            br#"{"error":"not found"}"#,
        ),
    );
    exchange(
        &mut s,
        &request(
            "OPTIONS",
            "api.example.test:8080",
            "/v1/items",
            CURL,
            "Origin: http://portal.example.test\r\n",
            b"",
        ),
        &response(
            "204 No Content",
            "Allow: GET, POST, PUT, PATCH, DELETE\r\n",
            b"",
        ),
    );
    exchange(
        &mut s,
        &request(
            "GET",
            "api.example.test:8080",
            "/v1/report",
            CURL,
            auth,
            b"",
        ),
        &response(
            "500 Internal Server Error",
            "Content-Type: text/plain\r\n",
            b"internal error",
        ),
    );
    s.close();
    sc.advance(20 * NS_PER_MS);
}

fn updates(sc: &mut Scenario) {
    let updates = server([198, 51, 100, 20]);
    // Software update check: HEAD then a download of a binary.
    let mut s = sc.tcp_open(client(20), updates, &TcpOptions::new(80));
    exchange(
        &mut s,
        &request(
            "HEAD",
            "updates.example.net",
            "/releases/latest.bin",
            UPDATER,
            "",
            b"",
        ),
        &response(
            "200 OK",
            "Content-Type: application/octet-stream\r\nX-Checksum: 9a1f\r\n",
            b"",
        ),
    );
    let binary: Vec<u8> = (0..4096u32)
        .map(|i| u8::try_from(i.wrapping_mul(31) % 251).unwrap_or(0))
        .collect();
    let mut elf = b"\x7fELF".to_vec();
    elf.extend_from_slice(&binary);
    exchange(
        &mut s,
        &request(
            "GET",
            "updates.example.net",
            "/releases/latest.bin",
            UPDATER,
            "",
            b"",
        ),
        &response("200 OK", "Content-Type: application/octet-stream\r\n", &elf),
    );
    s.close();
    sc.advance(20 * NS_PER_MS);
}

fn unanswered(sc: &mut Scenario) {
    let cdn = server([203, 0, 113, 12]);
    // CDN request left without response (connection closed by the client).
    let mut s = sc.tcp_open(client(21), cdn, &TcpOptions::new(80));
    s.client_send(&request(
        "GET",
        "cdn.example.test",
        "/fonts/inter.woff2",
        CHROME,
        "Accept: */*\r\n",
        b"",
    ));
    s.close();
    sc.advance(20 * NS_PER_MS);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_are_deterministic() {
        let mut a = Scenario::new();
        round(&mut a);
        let mut b = Scenario::new();
        round(&mut b);
        assert_eq!(a.packets(), b.packets());
        assert!(a.len() > 60);
    }
}
