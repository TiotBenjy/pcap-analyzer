//! The `smb` analyzer and its parsers.
//!
//! - [`browser`]: NetBIOS datagram service (UDP 138) and `\MAILSLOT\BROWSE` host/domain/local
//!   master announcements (MS-BRWS);
//! - [`message`]: SMB1 / SMB2-3 message recognition over TCP (139/445), NEGOTIATE response;
//! - [`ntlmssp`]: NTLMSSP NEGOTIATE/CHALLENGE/AUTHENTICATE and the hashcat lines (5500 / 5600);
//! - [`os`]: OS-version and `SV_TYPE_*` role labels;
//! - [`analyzer`]: the [`Analyzer`](crate::Analyzer) implementation, pairing the server challenge
//!   with the client response and emitting records (`smb_announces`, `smb_sessions`, generic
//!   credentials for the Credentials tab).

mod analyzer;
mod browser;
mod bytes;
mod message;
mod ntlmssp;
mod os;

pub use analyzer::{SmbAnalyzer, SmbConfig};

#[cfg(test)]
mod tests;
