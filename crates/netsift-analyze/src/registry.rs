//! Registry of the built-in analyzers, instantiated once per flow shard.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use crate::analyzer::{Analyzer, AnalyzerId};
use crate::connections::{ConnectionsAnalyzer, ConnectionsConfig};
use crate::core::CoreAnalyzer;
use crate::geo::GeoDb;
use crate::ports::{PortsAnalyzer, PortsConfig};

/// Settings of the `core` analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreConfig {
    /// Maximum number of hosts aggregated in memory per shard before a flush.
    pub max_pending_hosts: usize,
    /// Pending host observations are flushed when packet time advances this much (ns).
    pub host_flush_interval_ns: i64,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            max_pending_hosts: 16_384,
            host_flush_interval_ns: 60 * 1_000_000_000,
        }
    }
}

/// Settings and shared resources passed to every analyzer constructor. Analyzers read the
/// fields they need. Built with `AnalyzerConfig::default()` then field updates (the struct is
/// non-exhaustive, so new fields never break callers).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AnalyzerConfig {
    // --- per-analyzer settings: registration point, one field per analyzer, sorted ---
    pub connections: ConnectionsConfig,
    pub core: CoreConfig,
    pub ports: PortsConfig,
    // --- shared resources (read-only, shared by every shard), sorted ---
    /// `blobs/` directory of the session being imported (set by the engine).
    pub blobs_dir: Option<Arc<PathBuf>>,
    /// Country database (set by the engine when one is available): `hosts.country`.
    pub geo: Option<Arc<GeoDb>>,
}

/// Constructor of one analyzer instance. Closures may capture shared resources.
pub type Factory = Arc<dyn Fn(&AnalyzerConfig) -> Box<dyn Analyzer> + Send + Sync>;

/// Wraps a constructor into a [`Factory`].
pub fn factory(
    f: impl Fn(&AnalyzerConfig) -> Box<dyn Analyzer> + Send + Sync + 'static,
) -> Factory {
    Arc::new(f)
}

/// Built-in analyzers. Registration point: each analyzer adds **one line** in the sorted zone.
fn builtin() -> Vec<(AnalyzerId, Factory)> {
    vec![
        (CoreAnalyzer::ID, factory(CoreAnalyzer::boxed)),
        // --- analyzers: one line each, sorted alphabetically by id ---
        (ConnectionsAnalyzer::ID, factory(ConnectionsAnalyzer::boxed)),
        (PortsAnalyzer::ID, factory(PortsAnalyzer::boxed)),
    ]
}

/// The set of analyzers run by an import. Cheap to clone and shareable between threads: it
/// only holds constructors.
#[derive(Clone)]
pub struct Registry {
    config: AnalyzerConfig,
    factories: Vec<(AnalyzerId, Factory)>,
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registry")
            .field("config", &self.config)
            .field("analyzers", &self.ids())
            .finish_non_exhaustive()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::builtin(AnalyzerConfig::default())
    }
}

impl Registry {
    /// Every built-in analyzer.
    pub fn builtin(config: AnalyzerConfig) -> Self {
        Self {
            config,
            factories: builtin(),
        }
    }

    /// No analyzer (add some with [`Registry::with`]).
    pub fn empty(config: AnalyzerConfig) -> Self {
        Self {
            config,
            factories: Vec::new(),
        }
    }

    /// Adds an analyzer (replaces a registered one with the same id).
    #[must_use]
    pub fn with(
        mut self,
        id: AnalyzerId,
        constructor: impl Fn(&AnalyzerConfig) -> Box<dyn Analyzer> + Send + Sync + 'static,
    ) -> Self {
        self.factories.retain(|(i, _)| *i != id);
        self.factories.push((id, factory(constructor)));
        self
    }

    /// Keeps only the analyzers whose id satisfies `keep`.
    #[must_use]
    pub fn filtered(mut self, keep: impl Fn(AnalyzerId) -> bool) -> Self {
        self.factories.retain(|(id, _)| keep(*id));
        self
    }

    /// Identifiers of the registered analyzers, in call order.
    pub fn ids(&self) -> Vec<AnalyzerId> {
        self.factories.iter().map(|(id, _)| *id).collect()
    }

    pub fn config(&self) -> &AnalyzerConfig {
        &self.config
    }

    /// Mutable settings (the engine sets the shared resources of the session).
    pub fn config_mut(&mut self) -> &mut AnalyzerConfig {
        &mut self.config
    }

    /// Fresh instances for one shard, in registration order.
    pub fn build_shard(&self) -> Vec<Box<dyn Analyzer>> {
        self.factories
            .iter()
            .map(|(_, f)| f(&self.config))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_starts_with_core_and_ids_match_instances() {
        let registry = Registry::default();
        let ids = registry.ids();
        assert_eq!(ids.first(), Some(&AnalyzerId("core")));
        let instances = registry.build_shard();
        assert_eq!(
            instances.iter().map(|a| a.id()).collect::<Vec<_>>(),
            ids,
            "registered id and Analyzer::id must agree"
        );
        // Analyzers after `core` are sorted.
        let rest: Vec<_> = ids.iter().skip(1).collect();
        let mut sorted = rest.clone();
        sorted.sort();
        assert_eq!(rest, sorted);
    }

    #[test]
    fn filter_and_replace() {
        let registry = Registry::default().filtered(|id| id == CoreAnalyzer::ID);
        assert_eq!(registry.ids(), vec![CoreAnalyzer::ID]);
        let registry = registry.filtered(|id| id != CoreAnalyzer::ID);
        assert_eq!(registry.ids().len(), 0);
        let registry = registry
            .with(CoreAnalyzer::ID, CoreAnalyzer::boxed)
            .with(CoreAnalyzer::ID, CoreAnalyzer::boxed);
        assert_eq!(registry.ids(), vec![CoreAnalyzer::ID]);
        assert_eq!(registry.build_shard().len(), 1);
    }
}
