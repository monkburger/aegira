pub fn version() -> &'static str {
    option_env!("AEGIRA_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}

pub fn commit() -> &'static str {
    option_env!("AEGIRA_COMMIT").unwrap_or("unknown")
}

pub fn build_date() -> &'static str {
    option_env!("AEGIRA_BUILD_DATE").unwrap_or("unknown")
}

pub fn long() -> String {
    format!(
        "aegira version={} commit={} build_date={}",
        version(),
        commit(),
        build_date()
    )
}
