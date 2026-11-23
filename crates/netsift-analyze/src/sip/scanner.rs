//! User agents of SIP scanning tools. A match is a hint, not a proof: the header is declarative,
//! a tool can change it and legitimate software could reuse a name.

/// `(lower-case fragment of the user agent, canonical tool name)`, checked in order.
const TOOLS: &[(&str, &str)] = &[
    ("friendly-scanner", "SIPVicious"),
    ("sipvicious", "SIPVicious"),
    ("sipsak", "sipsak"),
    ("sipcli", "sipcli"),
    ("sip-scan", "sip-scan"),
    ("sipscan", "sip-scan"),
    ("smap", "smap"),
    ("iwar", "iWar"),
    ("sundayddr", "sundayddr"),
    ("vaxsipuseragent", "VaxSIPUserAgent"),
];

/// Canonical name of the scanning tool whose name appears in `agent` (`User-Agent`, else
/// `Server`), case-insensitively.
pub fn tool(agent: &str) -> Option<&'static str> {
    let lower = agent.to_ascii_lowercase();
    // `smap` is short: only as a whole word, so that "Bismap Phone" is not a scanner.
    TOOLS.iter().find_map(|(fragment, name)| {
        let found = if *fragment == "smap" {
            lower
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|w| w == "smap")
        } else {
            lower.contains(fragment)
        };
        found.then_some(*name)
    })
}

#[cfg(test)]
mod tests {
    use super::tool;

    #[test]
    fn known_tools_are_recognized() {
        assert_eq!(tool("friendly-scanner"), Some("SIPVicious"));
        assert_eq!(tool("sipvicious_svwar 0.3"), Some("SIPVicious"));
        assert_eq!(tool("SIPSAK 0.9.6"), Some("sipsak"));
        assert_eq!(tool("smap 0.6.0"), Some("smap"));
        assert_eq!(tool("iWar"), Some("iWar"));
        assert_eq!(tool("VaxSIPUserAgent/3.1"), Some("VaxSIPUserAgent"));
        assert_eq!(tool("Bismap Phone"), None);
        assert_eq!(tool("Softphone/3.1"), None);
    }
}
