use anyhow::{bail, Result};
use tracing::info;

use crate::{config::Config, engine::Engine, rules::Bundle, runtime};

pub struct Daemon {
    config: Config,
    bundle: Bundle,
    engine: Engine,
    config_path: String,
}

impl Daemon {
    pub fn new(config: Config, bundle: Bundle, config_path: String) -> Result<Self> {
        if config.listener.bind.trim().is_empty() {
            bail!("listener.bind is required");
        }

        let engine = Engine::compile(&bundle)?;

        Ok(Self {
            config,
            bundle,
            engine,
            config_path,
        })
    }

    pub async fn run(&self) -> Result<()> {
        info!(
            listen = %self.config.listener.bind,
            sites = self.config.sites.len(),
            backends = self.config.backends.len(),
            rules = self.bundle.rules.len(),
            compiled_rules = self.engine_rule_count(),
            "aegira scaffold active"
        );
        runtime::serve(self.config.clone(), self.engine.clone(), &self.config_path).await
    }

    fn engine_rule_count(&self) -> usize {
        self.engine.len()
    }
}
