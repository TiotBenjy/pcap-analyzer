//! Human-readable label for the announced OS version of a browser announcement. The `SV_TYPE_*`
//! role bits are decoded for display in `netsift_store::smb` (next to the stored column).

/// Readable label for an announced OS version (`major.minor`), falling back to the raw numbers.
pub fn os_label(major: u8, minor: u8) -> String {
    let known = match (major, minor) {
        (10, 0) => "Windows 10 / Server 2016+",
        (6, 3) => "Windows 8.1 / Server 2012 R2",
        (6, 2) => "Windows 8 / Server 2012",
        (6, 1) => "Windows 7 / Server 2008 R2",
        (6, 0) => "Windows Vista / Server 2008",
        (5, 2) => "Windows XP x64 / Server 2003",
        (5, 1) => "Windows XP",
        (5, 0) => "Windows 2000",
        (4, _) => "Windows NT 4.0",
        (0, 0) => "Unknown",
        _ => "",
    };
    if known.is_empty() {
        format!("Windows {major}.{minor}")
    } else {
        known.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_labels() {
        assert_eq!(os_label(10, 0), "Windows 10 / Server 2016+");
        assert_eq!(os_label(6, 1), "Windows 7 / Server 2008 R2");
        assert_eq!(os_label(4, 9), "Windows NT 4.0");
        assert_eq!(os_label(7, 3), "Windows 7.3");
        assert_eq!(os_label(0, 0), "Unknown");
    }
}
