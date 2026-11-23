//! FTP sessions (RFC 959, RFC 2428) for the FTP view: a passive session that downloads an image
//! and uploads a text file (the client opening the data connection before `STOR`), an active
//! session (`PORT`, data from port 20) with a listing and a multi-line `FEAT` reply, an `EPSV`
//! session over IPv6, a refused login, an interrupted download (`426`) and an `AUTH TLS` session.
//!
//! Hosts are in documentation ranges and are not used by the other scenarios (their connections
//! never collide with them when traffic is merged).

use std::net::Ipv6Addr;

use crate::images;
use crate::packet::Host;
use crate::scenario::{ParkedTcp, Scenario, TcpOptions, TcpSession};
use crate::time::NS_PER_MS;

/// Hosts of the FTP sessions.
pub mod ftp_hosts {
    use super::{Host, Ipv6Addr};

    /// LAN workstation, 192.168.1.31.
    pub fn client() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x31], [192, 168, 1, 31])
    }

    /// Second LAN workstation, 192.168.1.32.
    pub fn client2() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x32], [192, 168, 1, 32])
    }

    /// LAN file server, 192.168.1.33.
    pub fn server() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x33], [192, 168, 1, 33])
    }

    /// Remote FTP mirror 203.0.113.21, reached through the router MAC.
    pub fn mirror() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01], [203, 0, 113, 21])
    }

    /// Workstation over IPv6, `2001:db8:1::31`.
    pub fn client_v6() -> Host {
        Host::v6(
            [0x02, 0x00, 0x5e, 0x10, 0x00, 0x31],
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x31),
        )
    }

    /// File server over IPv6, `2001:db8:1::33`.
    pub fn server_v6() -> Host {
        Host::v6(
            [0x02, 0x00, 0x5e, 0x10, 0x00, 0x33],
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x33),
        )
    }
}

/// Password of the passive session (tests check it never leaks).
pub const SECRET: &str = "Tr0ub4dor-fixture";
/// Text file uploaded by the passive session.
pub const REPORT: &[u8] = b"quarterly report\r\nrevenue: 42\r\n";
/// Listing returned by the active session.
pub const LISTING: &str = "-rw-r--r--   1 ftp ftp      2048 Nov 20 10:00 notes.txt\r\n\
                           drwxr-xr-x   2 ftp ftp      4096 Nov 20 10:00 archive\r\n";
/// Text file downloaded by the IPv6 session.
pub const README: &[u8] = b"Welcome to the mirror.\n";

/// What [`ftp_showcase`] produced, for assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpShowcase {
    /// Control sessions.
    pub sessions: usize,
    /// Transfer commands (files and listings).
    pub transfers: usize,
    /// Transfers expected to be stored as objects.
    pub stored: usize,
    /// The downloaded image.
    pub image: Vec<u8>,
}

/// Runs `f` on a parked connection.
fn on(sc: &mut Scenario, conn: &mut ParkedTcp, f: impl FnOnce(&mut TcpSession<'_>)) {
    let mut s = sc.resume(conn);
    f(&mut s);
    *conn = s.park();
}

fn close(sc: &mut Scenario, conn: ParkedTcp) {
    sc.resume(&conn).close();
}

/// `h1,h2,h3,h4,p1,p2` of an IPv4 host and a port.
fn host_port(host: Host, port: u16) -> String {
    let ip = host.ipv4().map_or([0; 4], |ip| ip.octets());
    let [hi, lo] = port.to_be_bytes();
    format!("{},{},{},{},{hi},{lo}", ip[0], ip[1], ip[2], ip[3])
}

/// Opens a control connection and logs in (`230` when `accepted`).
fn login(
    sc: &mut Scenario,
    client: Host,
    server: Host,
    user: &str,
    password: &str,
    accepted: bool,
) -> ParkedTcp {
    let mut s = sc.tcp_open(client, server, &TcpOptions::new(21));
    s.server_send(b"220 (vsFTPd 3.0.5)\r\n");
    s.client_send(format!("USER {user}\r\n").as_bytes());
    s.server_send(b"331 Please specify the password.\r\n");
    s.client_send(format!("PASS {password}\r\n").as_bytes());
    if accepted {
        s.server_send(b"230 Login successful.\r\n");
    } else {
        s.server_send(b"530 Login incorrect.\r\n");
    }
    s.park()
}

fn quit(sc: &mut Scenario, mut ctl: ParkedTcp) {
    on(sc, &mut ctl, |s| {
        s.client_send(b"QUIT\r\n");
        s.server_send(b"221 Goodbye.\r\n");
    });
    close(sc, ctl);
}

/// Passive download: `PASV`, `RETR`, data from the server, `226`.
pub fn passive_download(
    sc: &mut Scenario,
    ctl: &mut ParkedTcp,
    client: Host,
    server: Host,
    path: &str,
    content: &[u8],
    data_port: u16,
) {
    on(sc, ctl, |s| {
        s.client_send(b"PASV\r\n");
        s.server_send(
            format!(
                "227 Entering Passive Mode ({}).\r\n",
                host_port(server, data_port)
            )
            .as_bytes(),
        );
        s.client_send(format!("RETR {path}\r\n").as_bytes());
    });
    let mut data = sc
        .tcp_open(client, server, &TcpOptions::new(data_port))
        .park();
    on(sc, ctl, |s| {
        s.server_send(b"150 Opening BINARY mode data connection.\r\n");
    });
    on(sc, &mut data, |s| {
        s.server_send(content);
    });
    close(sc, data);
    on(sc, ctl, |s| {
        s.server_send(b"226 Transfer complete.\r\n");
    });
}

/// Passive: download an image, then upload a file with the data connection opened first.
fn passive_session(sc: &mut Scenario, image: &[u8]) {
    let client = ftp_hosts::client();
    let server = ftp_hosts::server();
    let mut ctl = login(sc, client, server, "alice", SECRET, true);
    on(sc, &mut ctl, |s| {
        s.client_send(b"SYST\r\n");
        s.server_send(b"215 UNIX Type: L8\r\n");
        s.client_send(b"TYPE I\r\n");
        s.server_send(b"200 Switching to Binary mode.\r\n");
    });
    passive_download(
        sc,
        &mut ctl,
        client,
        server,
        "photos/harbour.png",
        image,
        50_021,
    );
    sc.advance(200 * NS_PER_MS);
    on(sc, &mut ctl, |s| {
        s.client_send(b"PASV\r\n");
        s.server_send(
            format!(
                "227 Entering Passive Mode ({})\r\n",
                host_port(server, 50_022)
            )
            .as_bytes(),
        );
    });
    let mut data = sc.tcp_open(client, server, &TcpOptions::new(50_022)).park();
    on(sc, &mut ctl, |s| {
        s.client_send(b"STOR report.txt\r\n");
        s.server_send(b"150 Ok to send data.\r\n");
    });
    on(sc, &mut data, |s| {
        s.client_send(REPORT);
    });
    close(sc, data);
    on(sc, &mut ctl, |s| {
        s.server_send(b"226 Transfer complete.\r\n");
    });
    quit(sc, ctl);
    sc.advance(500 * NS_PER_MS);
}

/// Active: multi-line FEAT, PORT, LIST from port 20.
fn active_session(sc: &mut Scenario) {
    let client2 = ftp_hosts::client2();
    let server = ftp_hosts::server();
    let mut ctl = login(sc, client2, server, "bob", "hunter2-fixture", true);
    on(sc, &mut ctl, |s| {
        s.client_send(b"FEAT\r\n");
        s.server_send(b"211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n211 End\r\n");
        s.client_send(format!("PORT {}\r\n", host_port(client2, 41_000)).as_bytes());
        s.server_send(b"200 PORT command successful. Consider using PASV.\r\n");
        s.client_send(b"LIST -la\r\n");
    });
    let opts = TcpOptions {
        client_port: Some(20),
        ..TcpOptions::new(41_000)
    };
    let mut data = sc.tcp_open(server, client2, &opts).park();
    on(sc, &mut ctl, |s| {
        s.server_send(b"150 Here comes the directory listing.\r\n");
    });
    on(sc, &mut data, |s| {
        s.client_send(LISTING.as_bytes());
    });
    close(sc, data);
    on(sc, &mut ctl, |s| {
        s.server_send(b"226 Directory send OK.\r\n");
    });
    quit(sc, ctl);
    sc.advance(500 * NS_PER_MS);
}

/// EPSV over IPv6, anonymous.
fn epsv_session(sc: &mut Scenario) {
    let (client6, server6) = (ftp_hosts::client_v6(), ftp_hosts::server_v6());
    let mut ctl = login(
        sc,
        client6,
        server6,
        "anonymous",
        "guest@example.test",
        true,
    );
    on(sc, &mut ctl, |s| {
        s.client_send(b"EPSV\r\n");
        s.server_send(b"229 Entering Extended Passive Mode (|||50023|)\r\n");
        s.client_send(b"RETR pub/README\r\n");
    });
    let mut data = sc
        .tcp_open(client6, server6, &TcpOptions::new(50_023))
        .park();
    on(sc, &mut ctl, |s| {
        s.server_send(b"150 Opening BINARY mode data connection for pub/README.\r\n");
    });
    on(sc, &mut data, |s| {
        s.server_send(README);
    });
    close(sc, data);
    on(sc, &mut ctl, |s| {
        s.server_send(b"226 Transfer complete.\r\n");
    });
    quit(sc, ctl);
    sc.advance(500 * NS_PER_MS);
}

/// Refused logins (two attempts).
fn refused_session(sc: &mut Scenario) {
    let client2 = ftp_hosts::client2();
    let mut ctl = login(
        sc,
        client2,
        ftp_hosts::mirror(),
        "admin",
        "wrong-fixture",
        false,
    );
    on(sc, &mut ctl, |s| {
        s.client_send(b"USER admin\r\n");
        s.server_send(b"331 Please specify the password.\r\n");
        s.client_send(b"PASS admin123-fixture\r\n");
        s.server_send(b"530 Login incorrect.\r\n");
    });
    quit(sc, ctl);
    sc.advance(500 * NS_PER_MS);
}

/// Interrupted download: part of the file, then 426.
fn interrupted_session(sc: &mut Scenario) {
    let client = ftp_hosts::client();
    let mut ctl = login(
        sc,
        client,
        ftp_hosts::mirror(),
        "carol",
        "pa55-fixture",
        true,
    );
    on(sc, &mut ctl, |s| {
        s.client_send(b"REST 0\r\n");
        s.server_send(b"350 Restart position accepted (0).\r\n");
        s.client_send(b"PASV\r\n");
        s.server_send(
            format!(
                "227 Entering Passive Mode ({})\r\n",
                host_port(ftp_hosts::mirror(), 50_024)
            )
            .as_bytes(),
        );
        s.client_send(b"RETR iso/image.bin\r\n");
    });
    let mut data = sc
        .tcp_open(client, ftp_hosts::mirror(), &TcpOptions::new(50_024))
        .park();
    on(sc, &mut ctl, |s| {
        s.server_send(
            b"150 Opening BINARY mode data connection for iso/image.bin (1048576 bytes).\r\n",
        );
    });
    on(sc, &mut data, |s| {
        s.server_send(&[0x5a; 6000]);
    });
    close(sc, data);
    on(sc, &mut ctl, |s| {
        s.client_send(b"ABOR\r\n");
        s.server_send(b"426 Failure writing network stream.\r\n");
        s.server_send(b"226 ABOR successful.\r\n");
    });
    quit(sc, ctl);
    sc.advance(500 * NS_PER_MS);
}

/// AUTH TLS: the rest is encrypted (random bytes stand for TLS records).
fn tls_session(sc: &mut Scenario) {
    let client2 = ftp_hosts::client2();
    let server = ftp_hosts::server();
    let mut s = sc.tcp_open(client2, server, &TcpOptions::new(21));
    s.server_send(b"220 Secure FTP ready\r\n");
    s.client_send(b"AUTH TLS\r\n");
    s.server_send(b"234 Proceed with negotiation.\r\n");
    s.client_send(&[
        0x16, 0x03, 0x01, 0x00, 0x2a, 0x01, 0x00, 0x00, 0x26, 0x03, 0x03,
    ]);
    s.server_send(&[0x16, 0x03, 0x03, 0x00, 0x10, 0x02, 0x00, 0x00, 0x0c]);
    s.close();
}

/// The FTP showcase (see the module documentation), starting at the scenario clock.
pub fn ftp_showcase(sc: &mut Scenario) -> FtpShowcase {
    let image = images::png(64, 48, 2);
    passive_session(sc, &image);
    active_session(sc);
    epsv_session(sc);
    refused_session(sc);
    interrupted_session(sc);
    tls_session(sc);
    FtpShowcase {
        sessions: 6,
        transfers: 5,
        stored: 3,
        image,
    }
}

/// Content the third host sends on the announced data port (never the transferred file).
pub const STOLEN: &[u8] = b"third-party content";
/// File downloaded by the client of [`ftp_cross_pair`].
pub const CROSS_FILE: &[u8] = b"genuine file content\n";

/// Data connections between other address pairs than their control (ADR-032), which must never
/// be paired: whether they reach the shard of the control depends on the number of shards.
///
/// 1. A third host (192.168.1.32) connects to the port announced by the server in its `227`
///    before the client does, and sends [`STOLEN`]; the client then downloads [`CROSS_FILE`].
/// 2. FXP: a client drives two servers; the second (the mirror) connects to the port announced
///    by the first, which stays without data connection.
pub fn ftp_cross_pair(sc: &mut Scenario) {
    let (client, other, server, mirror) = (
        ftp_hosts::client(),
        ftp_hosts::client2(),
        ftp_hosts::server(),
        ftp_hosts::mirror(),
    );
    let mut ctl = login(sc, client, server, "dave", "cross-fixture", true);
    on(sc, &mut ctl, |s| {
        s.client_send(b"PASV\r\n");
        s.server_send(
            format!(
                "227 Entering Passive Mode ({})\r\n",
                host_port(server, 50_031)
            )
            .as_bytes(),
        );
    });
    let mut thief = sc.tcp_open(other, server, &TcpOptions::new(50_031)).park();
    on(sc, &mut thief, |s| {
        s.server_send(STOLEN);
    });
    close(sc, thief);
    let mut data = sc.tcp_open(client, server, &TcpOptions::new(50_031)).park();
    on(sc, &mut ctl, |s| {
        s.client_send(b"RETR genuine.txt\r\n");
        s.server_send(b"150 Opening BINARY mode data connection.\r\n");
    });
    on(sc, &mut data, |s| {
        s.server_send(CROSS_FILE);
    });
    close(sc, data);
    on(sc, &mut ctl, |s| {
        s.server_send(b"226 Transfer complete.\r\n");
    });
    quit(sc, ctl);
    sc.advance(200 * NS_PER_MS);

    // FXP: PASV on the server, the mirror connects to it, the server sends the file.
    let mut ctl = login(sc, client, server, "erin", "fxp-fixture", true);
    on(sc, &mut ctl, |s| {
        s.client_send(b"PASV\r\n");
        s.server_send(
            format!(
                "227 Entering Passive Mode ({})\r\n",
                host_port(server, 50_032)
            )
            .as_bytes(),
        );
        s.client_send(b"RETR mirror.iso\r\n");
    });
    let mut fxp = sc.tcp_open(mirror, server, &TcpOptions::new(50_032)).park();
    on(sc, &mut ctl, |s| {
        s.server_send(b"150 Opening BINARY mode data connection.\r\n");
    });
    on(sc, &mut fxp, |s| {
        s.server_send(&[0x42; 3000]);
    });
    close(sc, fxp);
    on(sc, &mut ctl, |s| {
        s.server_send(b"226 Transfer complete.\r\n");
    });
    quit(sc, ctl);
}

/// One small passive session (login, download of `files/<i>.txt`), for the demo session.
pub fn ftp_round(sc: &mut Scenario, i: u32) {
    let (client, server) = (ftp_hosts::client(), ftp_hosts::server());
    let mut ctl = login(
        sc,
        client,
        server,
        &format!("user{}", i % 5),
        "demo-fixture",
        true,
    );
    let port = 51_000 + u16::try_from(i % 10_000).unwrap_or(0);
    let content = format!("demo file {i}\n");
    passive_download(
        sc,
        &mut ctl,
        client,
        server,
        &format!("files/{i}.txt"),
        content.as_bytes(),
        port,
    );
    quit(sc, ctl);
}
