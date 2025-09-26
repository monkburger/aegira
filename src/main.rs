use std::{
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
};

use aegira::{config::{Config, LogFormat, LogTarget}, daemon::Daemon, rules, version};
use anyhow::{Context, Result};
use clap::Parser;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt,
    fmt::writer::{BoxMakeWriter, MakeWriterExt},
    EnvFilter,
};

#[derive(Debug, Parser)]
#[command(name = "aegira", disable_version_flag = true)]
struct Cli {
    #[arg(long, default_value = "configs/aegira.toml")]
    config: PathBuf,
    #[arg(long)]
    check_config: bool,
    #[arg(long)]
    version: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.version {
        println!("{}", version::long());
        return Ok(());
    }

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = Config::load(&cli.config)?;
    let bundle = rules::load_bundle(&config.rules.entrypoint, config.rules.max_include_depth)?;
    config.validate(&bundle)?;

    if cli.check_config {
        // Run inline [[rule.test]] cases defined in the rule files.
        let test_results = rules::run_bundle_tests(&bundle)?;
        let failures: Vec<_> = test_results.iter().filter(|r| !r.passed).collect();
        if !failures.is_empty() {
            for f in &failures {
                eprintln!(
                    "FAIL rule {} test[{}]: input {:?} against target '{}' expected {} got {}",
                    f.rule_id,
                    f.test_idx,
                    f.input,
                    f.target,
                    if f.expected_match { "match" } else { "no_match" },
                    if f.actual_match { "match" } else { "no_match" },
                );
            }
            anyhow::bail!("{} inline rule test(s) failed", failures.len());
        }
        println!(
            "config ok: sites={} backends={} routes={} rules={} rule_tests={}",
            config.sites.len(),
            config.backends.len(),
            config.routes.len(),
            bundle.rules.len(),
            test_results.len(),
        );
        return Ok(());
    }

    let _logging_guards =
        init_logging(&config).with_context(|| "initialize logging from [logging] config")?;

    let config_path = cli.config.to_string_lossy().into_owned();
    let daemon = Daemon::new(config, bundle, config_path)?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async move { daemon.run().await })
}

fn init_logging(config: &Config) -> Result<Vec<WorkerGuard>> {
    let log_cfg = &config.logging;
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(log_cfg.level.clone()))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let mut guards = Vec::new();

    let writer: BoxMakeWriter = match log_cfg.write_to {
        LogTarget::Stdout => BoxMakeWriter::new(io::stdout),
        LogTarget::File => {
            let (file_writer, guard) = file_writer(&log_cfg.file)?;
            guards.push(guard);
            BoxMakeWriter::new(file_writer)
        }
        LogTarget::Both => {
            let (file_writer, guard) = file_writer(&log_cfg.file)?;
            guards.push(guard);
            BoxMakeWriter::new(io::stdout.and(file_writer))
        }
    };

    match log_cfg.format {
        LogFormat::Json => {
            fmt()
                .with_env_filter(filter)
                .json()
                .with_ansi(false)
                .with_writer(writer)
                .without_time()
                .init();
        }
        LogFormat::Text => {
            fmt()
                .with_env_filter(filter)
                .with_writer(writer)
                .without_time()
                .init();
        }
    }

    Ok(guards)
}

fn file_writer(path: &str) -> Result<(tracing_appender::non_blocking::NonBlocking, WorkerGuard)> {
    let target = Path::new(path);
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create log directory {}", parent.display()))?;
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(target)
        .with_context(|| format!("open log file {}", target.display()))?;
    Ok(tracing_appender::non_blocking(file))
}
