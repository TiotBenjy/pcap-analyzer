//! The `sip` analyzer: SIP messages over UDP and TCP port 5060 (`netsift_dissect::sip`), the
//! media they announce in SDP, the user agents of known SIP scanners, and the Digest
//! authorizations of requests (emitted as [`Record::Credential`](crate::Record::Credential)).
//!
//! - [`analyzer`]: the [`Analyzer`](crate::Analyzer) implementation, one record per message;
//! - [`scanner`]: user agents of SIP scanning tools.
//!
//! Dialogs and calls (messages grouped by Call-ID, which cross flows and shards) are built by the
//! store at the end of the import (`netsift_store::sip`).

mod analyzer;
pub mod scanner;

pub use analyzer::{SIP_PORT, SipAnalyzer, SipRecord, SipTransport};

#[cfg(test)]
mod tests;
