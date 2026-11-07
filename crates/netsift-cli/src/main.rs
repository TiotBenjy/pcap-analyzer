//! `netsift` command-line entry point.

fn version_line() -> String {
    format!("netsift {}", env!("CARGO_PKG_VERSION"))
}

fn main() {
    #[allow(clippy::print_stdout)] // a CLI prints to stdout by design
    {
        println!("{}", version_line());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert!(super::version_line().starts_with("netsift "));
    }
}
