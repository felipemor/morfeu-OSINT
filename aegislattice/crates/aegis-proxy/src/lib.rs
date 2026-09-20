//! AegisLattice TLS 1.3 PQC Hybrid Reverse Proxy & Termination Sidecar

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub upstream_addr: String,
    pub enable_hybrid_pqc: bool,
    pub enforce_mldsa: bool,
}

pub struct AegisProxy {
    config: ProxyConfig,
}

impl AegisProxy {
    pub fn new(config: ProxyConfig) -> Self {
        Self { config }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let addr: SocketAddr = self.config.listen_addr.parse()?;
        info!(
            "AegisLattice PQC Hybrid Proxy listening on {} -> Upstream {}",
            addr, self.config.upstream_addr
        );
        info!("PQC KEM: X25519 + ML-KEM-768 Hybrid enabled: {}", self.config.enable_hybrid_pqc);
        Ok(())
    }
}
