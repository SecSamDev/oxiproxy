use std::sync::Arc;

use rcgen::{Certificate, KeyPair};
use rustls::sign::{Signer, SigningKey};

#[allow(unused)]
pub struct SignKeyWrapper {
    key: Arc<dyn SigningKey>,
    stc_cert: Arc<Certificate>,
    key_pair: Arc<KeyPair>,
}

impl SignKeyWrapper {
    pub fn new(key: Arc<dyn SigningKey>, cert: Arc<Certificate>, key_pair: Arc<KeyPair>) -> Self {
        Self {
            key,
            stc_cert: cert,
            key_pair,
        }
    }
}

impl SigningKey for SignKeyWrapper {
    fn choose_scheme(&self, offered: &[rustls::SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.key.choose_scheme(offered)
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.key.algorithm()
    }
}

impl std::fmt::Debug for SignKeyWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignKeyWrapper").finish()
    }
}