//! Authentication exchanges for the Credentials view: SMTP AUTH (PLAIN, LOGIN, CRAM-MD5), POP3
//! `USER`/`PASS`, IMAP `LOGIN`, LDAP simple bind, HTTP Basic / Proxy-Authorization and HTTP
//! NTLM. FTP (`Scenario::ftp_login`), SNMP (`Scenario::snmp_get`) and SMB NTLM
//! (`Scenario::smb_ntlm`) live in the scenario builder.
//!
//! Every secret here is a fake, fixture-only value.

use crate::packet::Host;
use crate::proto::der;
use crate::proto::smb::{ntlmssp_authenticate, ntlmssp_challenge, ntlmssp_negotiate};
use crate::scenario::{FtpLogin, Scenario, SmbNtlm, SnmpGet, TcpOptions};
use crate::scenarios::hosts;

/// Hosts of the credential exchanges (documentation ranges only).
pub mod credential_hosts {
    use super::Host;

    /// Mail server (SMTP 587, POP3 110, IMAP 143), 192.168.1.25.
    pub fn mail_server() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x25], [192, 168, 1, 25])
    }

    /// Directory server (LDAP 389), 192.168.1.5 (the domain controller of `servers`).
    pub fn directory() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x05], [192, 168, 1, 5])
    }

    /// Intranet web server with Basic and NTLM authentication, 192.168.1.80.
    pub fn intranet() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x50], [192, 168, 1, 80])
    }

    /// Forward proxy (TCP 3128), 192.168.1.3.
    pub fn proxy() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x03], [192, 168, 1, 3])
    }

    /// A second workstation, 192.168.1.11.
    pub fn laptop() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x11], [192, 168, 1, 11])
    }
}

/// Standard base64 with padding (RFC 4648).
pub fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// SASL mechanism of an SMTP `AUTH` exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslMech {
    /// `AUTH PLAIN <initial response>`.
    Plain,
    /// `AUTH LOGIN`, then the user and the password after two `334` prompts.
    Login,
    /// `AUTH CRAM-MD5`: server challenge, client `user digest` (digest is a fixed fake value).
    CramMd5,
}

/// SMTP submission (587): banner, `EHLO`, `AUTH`, reply (`235` or `535`), `QUIT`.
pub fn smtp_auth(
    sc: &mut Scenario,
    client: Host,
    server: Host,
    mech: SaslMech,
    user: &str,
    password: &str,
    accepted: bool,
) {
    let mut s = sc.tcp_open(client, server, &TcpOptions::new(587));
    s.server_send(b"220 mail.example.test ESMTP\r\n");
    s.client_send(b"EHLO ws01.example.test\r\n");
    s.server_send(b"250-mail.example.test\r\n250-AUTH PLAIN LOGIN CRAM-MD5\r\n250 8BITMIME\r\n");
    match mech {
        SaslMech::Plain => {
            let token = base64(format!("\0{user}\0{password}").as_bytes());
            s.client_send(format!("AUTH PLAIN {token}\r\n").as_bytes());
        }
        SaslMech::Login => {
            s.client_send(b"AUTH LOGIN\r\n");
            s.server_send(b"334 VXNlcm5hbWU6\r\n");
            s.client_send(format!("{}\r\n", base64(user.as_bytes())).as_bytes());
            s.server_send(b"334 UGFzc3dvcmQ6\r\n");
            s.client_send(format!("{}\r\n", base64(password.as_bytes())).as_bytes());
        }
        SaslMech::CramMd5 => {
            s.client_send(b"AUTH CRAM-MD5\r\n");
            let challenge = base64(b"<1896.697170952@mail.example.test>");
            s.server_send(format!("334 {challenge}\r\n").as_bytes());
            let response = base64(format!("{user} b913a602c7eda7a495b4e6e7334d3890").as_bytes());
            s.client_send(format!("{response}\r\n").as_bytes());
        }
    }
    let reply: &[u8] = if accepted {
        b"235 2.7.0 Authentication successful\r\n"
    } else {
        b"535 5.7.8 Authentication credentials invalid\r\n"
    };
    s.server_send(reply);
    s.client_send(b"QUIT\r\n");
    s.server_send(b"221 2.0.0 Bye\r\n");
    s.close();
}

/// POP3 (110): banner, `USER`, `PASS`, `+OK`, `QUIT`.
pub fn pop3_login(sc: &mut Scenario, client: Host, server: Host, user: &str, password: &str) {
    let mut s = sc.tcp_open(client, server, &TcpOptions::new(110));
    s.server_send(b"+OK POP3 server ready\r\n");
    s.client_send(format!("USER {user}\r\n").as_bytes());
    s.server_send(b"+OK\r\n");
    s.client_send(format!("PASS {password}\r\n").as_bytes());
    s.server_send(b"+OK Logged in.\r\n");
    s.client_send(b"QUIT\r\n");
    s.server_send(b"+OK Logging out.\r\n");
    s.close();
}

/// IMAP (143): greeting, `a1 LOGIN user "password"`, tagged reply (`OK` or `NO`), logout.
pub fn imap_login(
    sc: &mut Scenario,
    client: Host,
    server: Host,
    user: &str,
    password: &str,
    accepted: bool,
) {
    let mut s = sc.tcp_open(client, server, &TcpOptions::new(143));
    s.server_send(b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ready\r\n");
    s.client_send(format!("a1 LOGIN {user} \"{password}\"\r\n").as_bytes());
    let reply: &[u8] = if accepted {
        b"* CAPABILITY IMAP4rev1\r\na1 OK LOGIN completed\r\n"
    } else {
        b"a1 NO [AUTHENTICATIONFAILED] Invalid credentials\r\n"
    };
    s.server_send(reply);
    s.client_send(b"a2 LOGOUT\r\n");
    s.server_send(b"* BYE\r\na2 OK LOGOUT completed\r\n");
    s.close();
}

/// `LDAPv3` `BindRequest` with simple authentication (`[APPLICATION 0]`, password `[0]`).
pub fn ldap_bind_request(message_id: i64, dn: &str, password: &str) -> Vec<u8> {
    let bind = [
        der::integer_i64(3),
        der::octet_string(dn.as_bytes()),
        der::tlv(0x80, password.as_bytes()),
    ]
    .concat();
    der::sequence(&[&der::integer_i64(message_id), &der::tlv(0x60, &bind)])
}

/// LDAP `BindResponse` (`[APPLICATION 1]`) with a result code (0 success, 49 invalid
/// credentials).
pub fn ldap_bind_response(message_id: i64, result_code: u8) -> Vec<u8> {
    let result = [
        der::tlv(0x0a, &[result_code]),
        der::octet_string(b""),
        der::octet_string(b""),
    ]
    .concat();
    der::sequence(&[&der::integer_i64(message_id), &der::tlv(0x61, &result)])
}

/// LDAP (389): one simple bind and its response, then unbind and close.
pub fn ldap_simple_bind(
    sc: &mut Scenario,
    client: Host,
    server: Host,
    dn: &str,
    password: &str,
    result_code: u8,
) {
    let mut s = sc.tcp_open(client, server, &TcpOptions::new(389));
    s.client_send(&ldap_bind_request(1, dn, password));
    s.server_send(&ldap_bind_response(1, result_code));
    // UnbindRequest ([APPLICATION 2], NULL).
    s.client_send(&der::sequence(&[&der::integer_i64(2), &[0x42, 0x00]]));
    s.close();
}

/// One HTTP GET with an `Authorization: Basic` header (or `Proxy-Authorization` to a proxy on
/// 3128 with an absolute target) and a `200` reply.
pub fn http_basic(
    sc: &mut Scenario,
    client: Host,
    server: Host,
    user: &str,
    password: &str,
    proxy: bool,
) {
    let token = base64(format!("{user}:{password}").as_bytes());
    let (port, target, header) = if proxy {
        (
            3128,
            "http://updates.example.test/feed.xml",
            "Proxy-Authorization",
        )
    } else {
        (80, "/admin/status", "Authorization")
    };
    let mut s = sc.tcp_open(client, server, &TcpOptions::new(port));
    s.client_send(
        format!(
            "GET {target} HTTP/1.1\r\nHost: intranet.example.test\r\nUser-Agent: curl/8.5.0\r\n\
             {header}: Basic {token}\r\n\r\n"
        )
        .as_bytes(),
    );
    s.server_send(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok");
    s.close();
}

/// HTTP NTLM handshake on one connection: `401` with `WWW-Authenticate: NTLM`, NEGOTIATE,
/// `401` with the CHALLENGE, AUTHENTICATE, `200`.
pub fn http_ntlm(sc: &mut Scenario, client: Host, server: Host, auth: &SmbNtlm) {
    let mut s = sc.tcp_open(client, server, &TcpOptions::new(80));
    let get = |extra: &str| {
        format!("GET /intranet/ HTTP/1.1\r\nHost: intranet.example.test\r\n{extra}\r\n")
            .into_bytes()
    };
    let unauthorized = |www: &str| {
        format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: {www}\r\nContent-Length: 0\r\n\r\n")
            .into_bytes()
    };
    s.client_send(&get(""));
    s.server_send(&unauthorized("NTLM"));
    s.client_send(&get(&format!(
        "Authorization: NTLM {}\r\n",
        base64(&ntlmssp_negotiate())
    )));
    let challenge = ntlmssp_challenge(auth.server_challenge, &auth.domain);
    s.server_send(&unauthorized(&format!("NTLM {}", base64(&challenge))));
    let authenticate = ntlmssp_authenticate(
        &auth.domain,
        &auth.user,
        &auth.workstation,
        &auth.lm_response,
        &auth.nt_response,
    );
    s.client_send(&get(&format!(
        "Authorization: NTLM {}\r\n",
        base64(&authenticate)
    )));
    s.server_send(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 4\r\n\r\n<p/>");
    s.close();
}

/// One exchange of every credential emitter (fake secrets): FTP, SNMP v2c, HTTP Basic, HTTP
/// Proxy-Authorization, HTTP `NTLMv2`, SMB `NTLMv1`, SMTP PLAIN / LOGIN / CRAM-MD5, POP3, IMAP
/// (rejected), LDAP simple bind.
pub fn credentials_showcase(sc: &mut Scenario) {
    use credential_hosts::{directory, intranet, laptop, mail_server, proxy};
    let ws = hosts::workstation();
    sc.ftp_login(ws, hosts::ftp_server(), &FtpLogin::default());
    sc.snmp_get(ws, hosts::router(), &SnmpGet::default());
    http_basic(sc, ws, intranet(), "admin", "basic-fixture", false);
    http_basic(sc, laptop(), proxy(), "proxyuser", "proxy-fixture", true);
    http_ntlm(sc, laptop(), intranet(), &SmbNtlm::v2("mmartin", "CONTOSO"));
    sc.smb_ntlm(
        laptop(),
        hosts::file_server(),
        &SmbNtlm::v1("svc_backup", "CONTOSO"),
    );
    smtp_auth(
        sc,
        ws,
        mail_server(),
        SaslMech::Plain,
        "alice@example.test",
        "smtp-fixture",
        true,
    );
    smtp_auth(
        sc,
        laptop(),
        mail_server(),
        SaslMech::Login,
        "bob@example.test",
        "login-fixture",
        true,
    );
    smtp_auth(
        sc,
        laptop(),
        mail_server(),
        SaslMech::CramMd5,
        "carol",
        "",
        true,
    );
    pop3_login(sc, ws, mail_server(), "alice", "pop-fixture");
    imap_login(sc, laptop(), mail_server(), "bob", "imap-fixture", false);
    ldap_simple_bind(
        sc,
        ws,
        directory(),
        "cn=svc_ldap,ou=services,dc=corp,dc=example",
        "ldap-fixture",
        0,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(b"demo:demo-only"), "ZGVtbzpkZW1vLW9ubHk=");
    }

    #[test]
    fn ldap_bind_encoding() {
        assert_eq!(
            ldap_bind_request(1, "", ""),
            vec![
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00
            ]
        );
        assert_eq!(
            ldap_bind_response(1, 0),
            vec![
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00
            ]
        );
    }

    #[test]
    fn showcase_is_deterministic() {
        let mut a = Scenario::new();
        credentials_showcase(&mut a);
        let mut b = Scenario::new();
        credentials_showcase(&mut b);
        assert_eq!(a.packets(), b.packets());
        assert!(a.len() > 100);
    }
}
