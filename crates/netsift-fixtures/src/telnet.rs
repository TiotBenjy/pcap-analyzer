//! Telnet sessions (TCP 23 and 2323) for the Telnet view: option negotiation (`ECHO`, `SGA`,
//! `TTYPE`, `NAWS`, `NEW-ENVIRON`, `LINEMODE`), logins typed at `login:` / `Password:` prompts
//! with their echoes, a rejected then accepted login, a session longer than the transcript bound,
//! and segments that split `IAC` sequences.
//!
//! Hosts are invented (documentation ranges only); every password is a fake, fixture-only value.

use std::fmt::Write as _;

use crate::packet::Host;
use crate::scenario::{Scenario, TcpOptions, TcpSession};
use crate::scenarios::hosts;
use crate::time::NS_PER_MS;

/// Telnet port.
pub const PORT: u16 = 23;
/// Alternative port of embedded devices.
pub const ALT_PORT: u16 = 2323;

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;
const EC: u8 = 247;
const ECHO: u8 = 1;
const SGA: u8 = 3;
const TTYPE: u8 = 24;
const NAWS: u8 = 31;
const LINEMODE: u8 = 34;
const NEW_ENVIRON: u8 = 39;

/// Hosts of the Telnet sessions.
pub mod telnet_hosts {
    use super::{Host, hosts};

    /// Legacy Unix server, 192.168.1.23.
    pub fn unix_server() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x23], [192, 168, 1, 23])
    }

    /// Managed switch (Cisco-like prompts), 192.168.1.2.
    pub fn switch() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x02], [192, 168, 1, 2])
    }

    /// IP camera with Telnet on 2323, 192.168.1.70.
    pub fn camera() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x70], [192, 168, 1, 70])
    }

    /// The analyst workstation, 192.168.1.10.
    pub fn workstation() -> Host {
        hosts::workstation()
    }

    /// A second client, 192.168.1.11.
    pub fn laptop() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x11], [192, 168, 1, 11])
    }
}

/// Expected results of [`telnet_showcase`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShowcaseCounts {
    pub sessions: u64,
    pub clients: u64,
    pub servers: u64,
    /// Sessions where a password was typed.
    pub logins: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub truncated: u64,
    /// Credentials emitted (one per password typed).
    pub credentials: u64,
}

/// Counts of [`telnet_showcase`].
pub const SHOWCASE: ShowcaseCounts = ShowcaseCounts {
    sessions: 6,
    clients: 2,
    servers: 3,
    logins: 6,
    accepted: 5,
    rejected: 1,
    truncated: 1,
    credentials: 9,
};

/// Typing delay between two keystrokes.
const KEY_GAP_NS: i64 = 120 * NS_PER_MS;

/// Client keystrokes one segment each, echoed by the server when `echo`.
fn type_text(s: &mut TcpSession<'_>, text: &str, echo: bool) {
    for b in text.bytes() {
        s.scenario().advance(KEY_GAP_NS);
        s.client_send(&[b]);
        if echo {
            s.server_send(&[b]);
        }
    }
}

/// `Enter` in character mode (`CR NUL`), echoed as `CR LF` when `echo`.
fn enter(s: &mut TcpSession<'_>, echo: bool) {
    s.scenario().advance(KEY_GAP_NS);
    s.client_send(b"\r\0");
    if echo {
        s.server_send(b"\r\n");
    }
}

/// Server side of the usual negotiation: echo and suppress-go-ahead by the server, terminal type
/// and window size asked from the client.
fn negotiate_basic(s: &mut TcpSession<'_>, terminal: &str, cols: u16, rows: u16) {
    s.server_send(&[
        IAC, DO, TTYPE, IAC, DO, NAWS, IAC, WILL, ECHO, IAC, WILL, SGA,
    ]);
    let mut reply = vec![
        IAC, WILL, TTYPE, IAC, WILL, NAWS, IAC, DO, ECHO, IAC, DO, SGA,
    ];
    reply.extend([IAC, SB, NAWS]);
    for b in cols.to_be_bytes().into_iter().chain(rows.to_be_bytes()) {
        reply.push(b);
        if b == IAC {
            reply.push(IAC);
        }
    }
    reply.extend([IAC, SE]);
    s.client_send(&reply);
    s.server_send(&[IAC, SB, TTYPE, 1, IAC, SE]);
    let mut ttype = vec![IAC, SB, TTYPE, 0];
    ttype.extend(terminal.bytes());
    ttype.extend([IAC, SE]);
    s.client_send(&ttype);
}

/// Successful login on a Unix host, character mode with server echo, then a few commands.
pub fn unix_login(sc: &mut Scenario, client: Host, server: Host, user: &str, password: &str) {
    let mut s = sc.tcp_open(client, server, &TcpOptions::new(PORT));
    negotiate_basic(&mut s, "XTERM", 80, 24);
    s.server_send(b"\r\nOpenBSD/i386 (oof) (ttyp2)\r\n\r\nlogin: ");
    type_text(&mut s, user, true);
    enter(&mut s, true);
    s.server_send(b"Password:");
    type_text(&mut s, password, false);
    enter(&mut s, false);
    s.server_send(
        b"\r\nLast login: Sat Nov 27 20:11:43 on ttyp2 from 192.168.1.10\r\n\
          Warning: no Kerberos tickets issued.\r\n\
          \x1b[1mWelcome to OpenBSD:\x1b[0m The proactively secure Unix-like operating system.\r\n\
          \r\n$ ",
    );
    type_text(&mut s, "ls -a", true);
    enter(&mut s, true);
    s.server_send(b".         ..        .cshrc    .login    .profile  .rhosts\r\n$ ");
    // A typo corrected with backspace: `BS SP BS` echo.
    type_text(&mut s, "unamx", true);
    s.client_send(&[0x7f]);
    s.server_send(b"\x08 \x08");
    type_text(&mut s, "e -a", true);
    enter(&mut s, true);
    s.server_send(b"OpenBSD oof 2.6 GENERIC#4 i386\r\n$ ");
    type_text(&mut s, "exit", true);
    enter(&mut s, true);
    s.server_send(b"logout\r\n");
    s.close();
}

/// Switch login: a wrong password (`% Login invalid`), then the right one, on `Username:` /
/// `Password:` prompts, ending at an enable prompt.
pub fn switch_retry(
    sc: &mut Scenario,
    client: Host,
    server: Host,
    user: &str,
    wrong: &str,
    password: &str,
) {
    let mut s = sc.tcp_open(client, server, &TcpOptions::new(PORT));
    s.server_send(&[IAC, WILL, ECHO, IAC, WILL, SGA, IAC, DO, NAWS]);
    s.client_send(&[IAC, DO, ECHO, IAC, DO, SGA, IAC, WONT, NAWS]);
    s.server_send(b"\r\n\r\nUser Access Verification\r\n\r\nUsername: ");
    type_text(&mut s, user, true);
    enter(&mut s, true);
    s.server_send(b"Password: ");
    type_text(&mut s, wrong, false);
    enter(&mut s, false);
    s.server_send(b"\r\n% Login invalid\r\n\r\nUsername: ");
    type_text(&mut s, user, true);
    enter(&mut s, true);
    s.server_send(b"Password: ");
    type_text(&mut s, password, false);
    enter(&mut s, false);
    s.server_send(b"\r\nsw-core-01>");
    type_text(&mut s, "show version", true);
    enter(&mut s, true);
    s.server_send(b"Switch Software, Version 15.2(7)E\r\nuptime is 3 weeks, 2 days\r\nsw-core-01>");
    type_text(&mut s, "exit", true);
    enter(&mut s, true);
    s.close();
}

/// Rich negotiation in line mode (client-side editing and echo): `LINEMODE`, `NEW-ENVIRON` with
/// `USER`, a terminal type and a window size, coloured output; the client sends whole lines, the
/// server echoes nothing. The user name comes from the environment (no `login:` prompt).
pub fn linemode_session(sc: &mut Scenario, client: Host, server: Host, user: &str, password: &str) {
    let mut s = sc.tcp_open(client, server, &TcpOptions::new(PORT));
    s.server_send(&[
        IAC,
        DO,
        TTYPE,
        IAC,
        DO,
        NAWS,
        IAC,
        DO,
        LINEMODE,
        IAC,
        DO,
        NEW_ENVIRON,
        IAC,
        WILL,
        SGA,
        IAC,
        DONT,
        ECHO,
    ]);
    s.client_send(&[
        IAC,
        WILL,
        TTYPE,
        IAC,
        WILL,
        NAWS,
        IAC,
        WILL,
        LINEMODE,
        IAC,
        WILL,
        NEW_ENVIRON,
        IAC,
        DO,
        SGA,
        IAC,
        WONT,
        ECHO,
    ]);
    // Server asks for USER; the client answers with USER and an undefined DISPLAY.
    s.server_send(&[IAC, SB, NEW_ENVIRON, 1, 0, b'U', b'S', b'E', b'R', IAC, SE]);
    let mut env = vec![IAC, SB, NEW_ENVIRON, 0, 0];
    env.extend(b"USER");
    env.push(1);
    env.extend(user.bytes());
    env.push(0);
    env.extend(b"DISPLAY");
    env.extend([IAC, SE]);
    s.client_send(&env);
    s.client_send(&[IAC, SB, NAWS, 0, 132, 0, 43, IAC, SE]);
    s.server_send(&[IAC, SB, TTYPE, 1, IAC, SE]);
    s.client_send(&[IAC, SB, TTYPE, 0, b'V', b'T', b'1', b'0', b'0', IAC, SE]);
    s.server_send(&[IAC, SB, LINEMODE, 1, 3, IAC, SE]);
    s.client_send(&[IAC, SB, LINEMODE, 1, 7, IAC, SE]);
    s.server_send(b"\x1b[2J\x1b[HLinux 6.1 (legacy-db)\r\n\r\nPassword for ");
    s.server_send(user.as_bytes());
    s.server_send(b": ");
    s.client_send(format!("{password}\r\n").as_bytes());
    s.server_send(b"\r\n\x1b]0;legacy-db\x07\x1b[32mlegacy-db\x1b[0m:~% ");
    s.client_send(b"uptime\r\n");
    s.server_send(
        b" 10:42:01 up 812 days,  3 users,  load average: 0.08, 0.03, 0.01\r\nlegacy-db:~% ",
    );
    s.client_send(b"logout\r\n");
    s.close();
}

/// Lines of server output of [`long_session`]: more than the transcript keeps.
pub const LONG_SESSION_LINES: usize = 2600;

/// A camera on port 2323 with a default account, dumping a long log after login (the transcript
/// is truncated).
pub fn long_session(sc: &mut Scenario, client: Host, server: Host, user: &str, password: &str) {
    let mut opts = TcpOptions::new(ALT_PORT);
    opts.mss = 1400;
    let mut s = sc.tcp_open(client, server, &opts);
    s.server_send(&[IAC, WILL, ECHO, IAC, WILL, SGA]);
    s.client_send(&[IAC, DO, ECHO, IAC, DO, SGA]);
    s.server_send(b"\r\nIPCam login: ");
    type_text(&mut s, user, true);
    enter(&mut s, true);
    s.server_send(b"Password: ");
    type_text(&mut s, password, false);
    enter(&mut s, false);
    s.server_send(b"\r\n\r\nBusyBox v1.19.4 built-in shell (ash)\r\n# ");
    type_text(&mut s, "logread", true);
    enter(&mut s, true);
    let mut log = String::new();
    for i in 0..LONG_SESSION_LINES {
        let _ = write!(
            log,
            "Jan  1 00:{:02}:{:02} ipcam user.info streamer[812]: frame {i} sent to 192.168.1.11\r\n",
            (i / 60) % 60,
            i % 60
        );
    }
    s.server_send(log.as_bytes());
    s.server_send(b"# ");
    type_text(&mut s, "exit", true);
    enter(&mut s, true);
    s.close();
}

/// Rejected logins on the camera (`Login incorrect` after each password), then the server
/// hangs up.
pub fn failed_login(sc: &mut Scenario, client: Host, server: Host, user: &str, passwords: &[&str]) {
    let mut s = sc.tcp_open(client, server, &TcpOptions::new(ALT_PORT));
    s.server_send(&[IAC, WILL, ECHO, IAC, WILL, SGA]);
    s.client_send(&[IAC, DO, ECHO, IAC, DO, SGA]);
    s.server_send(b"\r\nIPCam login: ");
    for (i, password) in passwords.iter().enumerate() {
        if i > 0 {
            s.server_send(b"IPCam login: ");
        }
        type_text(&mut s, user, true);
        enter(&mut s, true);
        s.server_send(b"Password: ");
        type_text(&mut s, password, false);
        enter(&mut s, false);
        s.scenario().advance(1_000 * NS_PER_MS);
        s.server_send(b"\r\nLogin incorrect\r\n");
    }
    s.close();
}

/// Segments that split `IAC` sequences: a negotiation cut after `IAC`, a sub-negotiation cut
/// inside its payload and before `SE`, an `IAC IAC` (data byte 255) cut in two, and an `IAC EC`
/// erase cut after `IAC`. The login succeeds.
pub fn split_iac(sc: &mut Scenario, client: Host, server: Host, user: &str, password: &str) {
    let mut s = sc.tcp_open(client, server, &TcpOptions::new(PORT));
    s.server_send(&[IAC]);
    s.server_send(&[WILL, ECHO, IAC, WILL]);
    s.server_send(&[SGA, IAC, DO, TTYPE]);
    s.client_send(&[IAC, WILL, TTYPE, IAC, DO, ECHO, IAC, DO, SGA]);
    s.server_send(&[IAC, SB, TTYPE, 1, IAC, SE]);
    s.client_send(&[IAC, SB, TTYPE, 0, b'A', b'N']);
    s.client_send(&[b'S', b'I', IAC]);
    s.client_send(&[SE]);
    s.server_send(b"\r\nbuild-01 login: ");
    // The user mistypes a letter and erases it with `IAC EC` (split), echoed `BS SP BS`.
    type_text(&mut s, user, true);
    s.client_send(b"x");
    s.server_send(b"x");
    s.client_send(&[IAC]);
    s.client_send(&[EC]);
    s.server_send(b"\x08 \x08");
    enter(&mut s, true);
    s.server_send(b"Password: ");
    type_text(&mut s, password, false);
    enter(&mut s, false);
    // Output with a data byte 255 escaped as `IAC IAC`, cut between the two.
    s.server_send(b"\r\nLast login: never\r\nbanner \xc3");
    s.server_send(&[IAC]);
    s.server_send(&[IAC, b'\r', b'\n', b'$', b' ']);
    type_text(&mut s, "exit", true);
    enter(&mut s, true);
    s.close();
}

/// Every Telnet session of the view, a few seconds apart (counts: [`SHOWCASE`]).
pub fn telnet_showcase(sc: &mut Scenario) {
    use telnet_hosts::{camera, laptop, switch, unix_server, workstation};
    unix_login(sc, workstation(), unix_server(), "fake", "user-fixture");
    sc.advance(2_000 * NS_PER_MS);
    switch_retry(
        sc,
        workstation(),
        switch(),
        "netadmin",
        "wrong-fixture",
        "switch-fixture",
    );
    sc.advance(2_000 * NS_PER_MS);
    linemode_session(sc, laptop(), unix_server(), "jdoe", "env-fixture");
    sc.advance(2_000 * NS_PER_MS);
    long_session(sc, laptop(), camera(), "root", "cam-fixture");
    sc.advance(2_000 * NS_PER_MS);
    failed_login(
        sc,
        workstation(),
        camera(),
        "admin",
        &["admin-fixture", "12345-fixture", "guess-fixture"],
    );
    sc.advance(2_000 * NS_PER_MS);
    split_iac(sc, workstation(), unix_server(), "ops", "split-fixture");
}

/// One periodic background session (switch login) for long demo captures.
pub fn telnet_round(sc: &mut Scenario, round: usize) {
    use telnet_hosts::{laptop, switch, workstation};
    let client = if round.is_multiple_of(2) {
        workstation()
    } else {
        laptop()
    };
    let mut s = sc.tcp_open(client, switch(), &TcpOptions::new(PORT));
    s.server_send(&[IAC, WILL, ECHO, IAC, WILL, SGA]);
    s.client_send(&[IAC, DO, ECHO, IAC, DO, SGA]);
    s.server_send(b"\r\nUsername: ");
    type_text(&mut s, "monitor", true);
    enter(&mut s, true);
    s.server_send(b"Password: ");
    type_text(&mut s, "monitor-fixture", false);
    enter(&mut s, false);
    s.server_send(b"\r\nsw-core-01>");
    type_text(&mut s, "show interfaces status", true);
    enter(&mut s, true);
    s.server_send(
        format!(
            "Port    Status       Vlan\r\nGi0/1   connected    10\r\nGi0/2   notconnect   {}\r\nsw-core-01>",
            10 + round % 5
        )
        .as_bytes(),
    );
    type_text(&mut s, "exit", true);
    enter(&mut s, true);
    s.close();
}
