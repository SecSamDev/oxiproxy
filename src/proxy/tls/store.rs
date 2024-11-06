use std::{collections::{BTreeMap, BTreeSet}, sync::{Arc, Mutex}};

use rcgen::generate_simple_self_signed;
use rustls::{ ClientConfig, ServerConfig};

use crate::proxy::tls::db::CaDb;

use super::{resolv::CertResolver, verify::AnyVerifier};

#[derive(Clone)]
pub struct TlsCertStore {
    pub sconfig: Arc<ServerConfig>,
    pub cconfig: Arc<ClientConfig>,
    pub pinned: Arc<Mutex<BTreeSet<String>>>
}

impl TlsCertStore {
    pub fn new(ca_location: &str, pinned : Arc<Mutex<BTreeSet<String>>>) -> std::io::Result<Self> {
        let db = CaDb::from_dir("CA".into(), ca_location)?;
        let verifier = Arc::new(AnyVerifier{});
        let cconfig = Arc::new(
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier.clone())
                .with_no_client_auth(),
        );
        let resolver = Arc::new(CertResolver::new(cconfig.clone(), Arc::new(db), pinned.clone()));
        let conf = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        let sconfig = Arc::new(conf);

        Ok(Self {
            cconfig,
            sconfig,
            pinned
        })
    }
    pub fn disable_addr(&self, addr: String) {
        let mut g = match self.pinned.lock() {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Pinned domain list is poisoned");
                let mut p = e.into_inner();
                *p = BTreeSet::new();
                p
            }
        };
        g.insert(addr);
    }

    pub fn is_disabled(&self, addr: &str) -> bool {
        let g = match self.pinned.lock() {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Pinned domain list is poisoned");
                let mut p = e.into_inner();
                *p = BTreeSet::new();
                p
            },
        };
        g.contains(addr)
    }
}